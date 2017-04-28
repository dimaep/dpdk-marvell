/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2017 Semihalf. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Semihalf nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_ethdev.h>
#include <rte_kvargs.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_vdev.h>

#include <drivers/mv_pp2.h>
#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_hif.h>
#include <drivers/mv_pp2_ppio.h>

#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/* bitmask with reserved hifs */
#define MRVL_MUSDK_HIFS_RESERVED 0x0F
/* bitmask with reserved bpools */
#define MRVL_MUSDK_BPOOLS_RESERVED 0x07
/* maximum number of available hifs */
#define MRVL_MUSDK_HIFS_MAX 9

/* maximum number of rx queues per port */
#define MRVL_PP2_RXQ_MAX 32
/* maximum number of tx queues per port */
#define MRVL_PP2_TXQ_MAX 8
/* minimum number of descriptors in tx queue */
#define MRVL_PP2_TXD_MIN 16
/* maximum number of descriptors in tx queue */
#define MRVL_PP2_TXD_MAX 1024
/* tx queue descriptors alignment */
#define MRVL_PP2_TXD_ALIGN 16
/* minimum number of descriptors in rx queue */
#define MRVL_PP2_RXD_MIN 16
/* maximum number of descriptors in rx queue */
#define MRVL_PP2_RXD_MAX 1024
/* rx queue descriptors alignment */
#define MRVL_PP2_RXD_ALIGN 16
/* maximum number of descriptors in tx aggregated queue */
#define MRVL_PP2_AGGR_TXQD_MAX 1024

#define MRVL_MAC_ADDRS_MAX 32
#define MRVL_MATCH_LEN 16
#define MRVL_PKT_OFFS 64
#define MRVL_PKT_EFFEC_OFFS (MRVL_PKT_OFFS + PP2_MH_SIZE)
#define MRVL_VLAN_TAG_SIZE 4

#define MRVL_IFACE_NAME_ARG "iface"

static const char *valid_args[] = {
	MRVL_IFACE_NAME_ARG,
	NULL
};

static int used_hifs = MRVL_MUSDK_HIFS_RESERVED;
static int used_bpools[PP2_NUM_PKT_PROC] = {
	MRVL_MUSDK_BPOOLS_RESERVED,
	MRVL_MUSDK_BPOOLS_RESERVED
};

struct mrvl_priv {
	struct pp2_hif *hif;
	struct pp2_bpool *bpool;
	struct pp2_ppio	*ppio;
	uint32_t dma_addr_high;

	struct pp2_ppio_params ppio_params;

	uint8_t pp_id;
	uint8_t ppio_id;
	uint8_t bpool_bit;
	uint8_t hif_bit;
};

struct mrvl_rxq {
	struct mrvl_priv *priv;
	struct rte_mempool *mp;
	int num_missing;
	int queue_id;
	int port_id;

	int cksum_enabled;
};

struct mrvl_txq {
	struct mrvl_priv *priv;
	int queue_id;
};

static inline int
mrvl_reserve_bit(int *bitmap, int max)
{
	int n = sizeof(*bitmap) * 8 - __builtin_clz(*bitmap);
	if (n >= max)
		return -1;

	*bitmap |= 1 << n;

	return n;
}

static int
mrvl_dev_configure(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	struct pp2_ppio_inq_params *inq_params;

	if (!dev->data->dev_conf.rxmode.hw_strip_crc) {
		RTE_LOG(INFO, PMD, "L2 CRC stripping is always enabled in hw\n");
		dev->data->dev_conf.rxmode.hw_strip_crc = 1;
	}

	inq_params = priv->ppio_params.inqs_params.tcs_params[0].inqs_params;
	if (inq_params)
		rte_free(inq_params);

	inq_params = rte_zmalloc_socket("inq_params",
				dev->data->nb_rx_queues * sizeof(*inq_params),
				0, rte_socket_id());
	if (!inq_params)
		return -ENOMEM;

	priv->ppio_params.inqs_params.tcs_params[0].num_in_qs = dev->data->nb_rx_queues;
	priv->ppio_params.inqs_params.tcs_params[0].inqs_params = inq_params;
	priv->ppio_params.outqs_params.num_outqs = dev->data->nb_tx_queues;

	return 0;
}

static int
mrvl_update_mru_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	uint16_t mru, curr_mtu;
	int ret;

	ret = pp2_ppio_get_mtu(priv->ppio, &curr_mtu);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to get current mtu\n");
		return ret;
	}

	if (curr_mtu == mtu)
		return 0;

	mru = mtu + PP2_MH_SIZE + ETHER_HDR_LEN + ETHER_CRC_LEN +
	      MRVL_VLAN_TAG_SIZE;

	ret = pp2_ppio_set_mru(priv->ppio, mru);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to set mru to %d\n", mru);
		return ret;
	}

	ret = pp2_ppio_set_mtu(priv->ppio, mtu);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to set mtu to %d\n", mtu);
		return ret;
	}

	return 0;
}

static int
mrvl_dev_start(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	char match[MRVL_MATCH_LEN];
	uint16_t size;
	int ret;

	snprintf(match, sizeof(match), "ppio-%d:%d", priv->pp_id, priv->ppio_id);
	priv->ppio_params.match = match;

	ret = pp2_ppio_init(&priv->ppio_params, &priv->ppio);
	if (ret)
		return ret;

	ret = mrvl_update_mru_mtu(dev, dev->data->mtu);
	if (ret) {
		pp2_ppio_deinit(priv->ppio);

		return ret;
	}

	return 0;
}

static void
mrvl_dev_stop(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;

	pp2_ppio_deinit(priv->ppio);
}

static int
mrvl_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	int ret;

	ret = pp2_ppio_enable(priv->ppio);
	if (ret)
		return ret;

	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

static int
mrvl_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	int ret;


	ret = pp2_ppio_disable(priv->ppio);
	if (ret)
		return ret;

	dev->data->dev_link.link_status = ETH_LINK_DOWN;

	return 0;
}

static void
mrvl_dev_close(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;

	if (priv->ppio_params.inqs_params.tcs_params[0].inqs_params)
		rte_free(priv->ppio_params.inqs_params.tcs_params[0].inqs_params);

	used_bpools[priv->pp_id] &= ~(1 << priv->bpool_bit);
	used_hifs &= ~(1 << priv->hif_bit);
}

static int
mrvl_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	/*
	 * TODO: how to get that from musdk? in fact there are apis for this
	 * stuff but not exported to userland (pp2_gop)
	 */
	dev->data->dev_link.link_status = ETH_LINK_UP;
	/* pass this as parameter? */
	dev->data->dev_link.link_speed = ETH_SPEED_NUM_10G;

	return 0;
}

static void
mrvl_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;

	pp2_ppio_set_uc_promisc(priv->ppio, 1);
	pp2_ppio_set_mc_promisc(priv->ppio, 1);
}

static void
mrvl_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct mrvl_priv *priv = dev->data->dev_private;

	pp2_ppio_set_uc_promisc(priv->ppio, 0);
	pp2_ppio_set_mc_promisc(priv->ppio, 0);
}

static void
mrvl_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	char buf[ETHER_ADDR_FMT_SIZE];
	int ret;

	ret = pp2_ppio_remove_mac_addr(priv->ppio, dev->data->mac_addrs[index].addr_bytes);
	if (ret) {
		ether_format_addr(buf, sizeof(buf), &dev->data->mac_addrs[index]);
		RTE_LOG(ERR, PMD, "Failed to remove mac %s\n", buf);
	}
}

static void
mrvl_mac_addr_add(struct rte_eth_dev *dev, struct ether_addr *mac_addr,
		  uint32_t index, uint32_t vmdq)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	char buf[ETHER_ADDR_FMT_SIZE];
	int ret;

	ret = pp2_ppio_add_mac_addr(priv->ppio, mac_addr->addr_bytes);
	if (ret) {
		ether_format_addr(buf, sizeof(buf), mac_addr);
		RTE_LOG(ERR, PMD, "Failed to add mac %s\n", buf);
	}
}

static void
mrvl_mac_addr_set(struct rte_eth_dev *dev, struct ether_addr *mac_addr)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	char buf[ETHER_ADDR_FMT_SIZE];
	struct ifreq req;
	int ret;

	/* TODO: temporary solution until musdk provides something similar */
	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, dev->data->name);
	memcpy(req.ifr_hwaddr.sa_data, mac_addr->addr_bytes, ETHER_ADDR_LEN);
	req.ifr_hwaddr.sa_family = ARPHRD_ETHER;

	ret = ioctl(fd, SIOCSIFHWADDR, &req);
	if (ret) {
		ether_format_addr(buf, sizeof(buf), mac_addr);
		RTE_LOG(ERR, PMD, "Failed to set mac %s\n", buf);
	}
}

static int
mrvl_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	int ret;

	ret = mrvl_update_mru_mtu(dev, mtu);
	if (ret)
		return ret;

	if (mtu > ETHER_MAX_LEN)
		dev->data->dev_conf.rxmode.jumbo_frame = 1;
	else
		dev->data->dev_conf.rxmode.jumbo_frame = 0;

	return 0;
}

static void
mrvl_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *info)
{
	info->max_rx_queues = MRVL_PP2_RXQ_MAX;
	info->max_tx_queues = MRVL_PP2_TXQ_MAX;
	info->max_mac_addrs = MRVL_MAC_ADDRS_MAX;

	info->rx_desc_lim.nb_max = MRVL_PP2_RXD_MAX;
	info->rx_desc_lim.nb_min = MRVL_PP2_RXD_MIN;
	info->rx_desc_lim.nb_align = MRVL_PP2_RXD_ALIGN;

	info->tx_desc_lim.nb_max = MRVL_PP2_TXD_MAX;
	info->tx_desc_lim.nb_min = MRVL_PP2_TXD_MIN;
	info->tx_desc_lim.nb_align = MRVL_PP2_TXD_ALIGN;

	info->rx_offload_capa = DEV_RX_OFFLOAD_IPV4_CKSUM |
				DEV_RX_OFFLOAD_UDP_CKSUM |
				DEV_RX_OFFLOAD_TCP_CKSUM;

	info->tx_offload_capa = DEV_TX_OFFLOAD_IPV4_CKSUM |
				DEV_TX_OFFLOAD_UDP_CKSUM |
				DEV_TX_OFFLOAD_TCP_CKSUM;
}

static int
mrvl_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct mrvl_priv *priv = dev->data->dev_private;

	return on ? pp2_ppio_add_vlan(priv->ppio, vlan_id) :
		    pp2_ppio_remove_vlan(priv->ppio, vlan_id);
}

static int
mrvl_fill_bpool(struct mrvl_rxq *rxq)
{
	struct pp2_buff_inf buff_inf;
	struct rte_mbuf *mbuf;
	uint64_t dma_addr;
	int ret;

	mbuf = rte_pktmbuf_alloc(rxq->mp);
	if (unlikely(!mbuf))
		return -ENOMEM;

	dma_addr = rte_mbuf_data_dma_addr_default(mbuf);

	if (unlikely(rxq->priv->dma_addr_high == -1))
		rxq->priv->dma_addr_high = dma_addr >> 32;

	/* all BPPEs must be located in the same 4GB address space */
	if (unlikely(rxq->priv->dma_addr_high != dma_addr >> 32)) {
		ret = -EFAULT;
		goto out_free_mbuf;
	}

	buff_inf.addr = dma_addr;
	buff_inf.cookie = (pp2_cookie_t)mbuf;

	ret = pp2_bpool_put_buff(rxq->priv->hif, rxq->priv->bpool,
				 &buff_inf);
	if (unlikely(ret)) {
		RTE_LOG(ERR, PMD, "Failed to release buffer to bm\n");
		ret = -EFAULT;
		goto out_free_mbuf;
	}

	return 0;
out_free_mbuf:
	rte_pktmbuf_free(mbuf);

	return ret;
}

static int
mrvl_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
		    unsigned int socket, const struct rte_eth_rxconf *conf,
		    struct rte_mempool *mp)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	struct mrvl_rxq *rxq;
	int i, ret;

	rxq = rte_zmalloc_socket("rxq", sizeof(*rxq), 0, socket);
	if (!rxq)
		return -ENOMEM;

	rxq->priv = priv;
	rxq->mp = mp;
	rxq->cksum_enabled = dev->data->dev_conf.rxmode.hw_ip_checksum;
	rxq->queue_id = idx;
	rxq->port_id = dev->data->port_id;

	dev->data->rx_queues[idx] = rxq;

	priv->ppio_params.inqs_params.tcs_params[0].inqs_params[idx].size = desc;

	for (i = 0; i < desc; i++) {
		ret = mrvl_fill_bpool(rxq);
		if (ret)
			goto out_free_mbufs;
	}

	return 0;
out_free_mbufs:
	for (; i >= 0; i--) {
		struct pp2_buff_inf inf;

		pp2_bpool_get_buff(rxq->priv->hif, rxq->priv->bpool, &inf);
		rte_pktmbuf_free((void *)inf.cookie);
	}
out_free_rxq:
	rte_free(rxq);
	return ret;
}

static int
mrvl_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
		    unsigned int socket, const struct rte_eth_txconf *conf)
{
	struct mrvl_priv *priv = dev->data->dev_private;
	struct mrvl_txq *txq;
	int i;

	txq = rte_zmalloc_socket("txq", sizeof(*txq), 0, socket);
	if (!txq)
		return -ENOMEM;

	txq->priv = priv;
	txq->queue_id = idx;
	dev->data->tx_queues[idx] = txq;

	priv->ppio_params.outqs_params.outqs_params[idx].size = desc;
	priv->ppio_params.outqs_params.outqs_params[idx].weight = 1;

	return 0;
}

static const struct eth_dev_ops mrvl_ops = {
	.dev_configure = mrvl_dev_configure,
	.dev_start = mrvl_dev_start,
	.dev_stop = mrvl_dev_stop,
	.dev_set_link_up = mrvl_dev_set_link_up,
	.dev_set_link_down = mrvl_dev_set_link_down,
	.dev_close = mrvl_dev_close,
	.link_update = mrvl_link_update,
	.promiscuous_enable = mrvl_promiscuous_enable,
	.promiscuous_disable = mrvl_promiscuous_disable,
	.mac_addr_remove = mrvl_mac_addr_remove,
	.mac_addr_add = mrvl_mac_addr_add,
	.mac_addr_set = mrvl_mac_addr_set,
	.mtu_set = mrvl_mtu_set,
	.stats_get = NULL,
	.stats_reset = NULL,
	.dev_infos_get = mrvl_dev_infos_get,
	.rxq_info_get = NULL,
	.txq_info_get = NULL,
	.vlan_filter_set = mrvl_vlan_filter_set,
	.rx_queue_start = NULL,
	.rx_queue_stop = NULL,
	.tx_queue_start = NULL,
	.tx_queue_stop = NULL,
	.rx_queue_setup = mrvl_rx_queue_setup,
	.rx_queue_release = NULL,
	.tx_queue_setup = mrvl_tx_queue_setup,
	.tx_queue_release = NULL,
	.flow_ctrl_get = NULL,
	.flow_ctrl_set = NULL,
	.rss_hash_update = NULL,
	.rss_hash_conf_get = NULL,
};

static uint32_t
mrvl_desc_to_packet_type_and_offset(struct pp2_ppio_desc *desc,
				    uint8_t *l3_offset, uint8_t *l4_offset)
{
	enum pp2_inq_l3_type l3_type;
	enum pp2_inq_l4_type l4_type;
	uint64_t packet_type;

	pp2_ppio_inq_desc_get_l3_info(desc, &l3_type, l3_offset);
	pp2_ppio_inq_desc_get_l4_info(desc, &l4_type, l4_offset);

	packet_type = RTE_PTYPE_INNER_L2_ETHER;

	switch (l3_type) {
	case PP2_INQ_L3_TYPE_IPV4_NO_OPTS:
		packet_type |= RTE_PTYPE_INNER_L3_IPV4;
		break;
	case PP2_INQ_L3_TYPE_IPV4_OK:
		packet_type |= RTE_PTYPE_INNER_L3_IPV4_EXT;
		break;
	case PP2_INQ_L3_TYPE_IPV4_TTL_ZERO:
		packet_type |= RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN;
		break;
	case PP2_INQ_L3_TYPE_IPV6_NO_EXT:
		packet_type |= RTE_PTYPE_INNER_L3_IPV6;
		break;
	case PP2_INQ_L3_TYPE_IPV6_EXT:
		packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	default:
		RTE_LOG(WARNING, PMD, "Failed to recognise l3 packet type\n");
		break;
	}

	switch (l4_type) {
	case PP2_INQ_L4_TYPE_TCP:
		packet_type |= RTE_PTYPE_INNER_L4_TCP;
		break;
	case PP2_INQ_L4_TYPE_UDP:
		packet_type |= RTE_PTYPE_INNER_L4_UDP;
		break;
	default:
		RTE_LOG(WARNING, PMD, "Failed to recognise l4 packet type\n");
		break;
	}

	return packet_type;
}

static uint64_t
mrvl_desc_to_ol_flags(struct pp2_ppio_desc *desc)
{
	enum pp2_inq_desc_status status = pp2_ppio_inq_desc_get_pkt_error(desc);

	if (likely(status == PP2_DESC_ERR_MAC_OK))
		return PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD;

	if (unlikely(status == PP2_DESC_ERR_IPV4_HDR))
		return PKT_RX_IP_CKSUM_BAD;

	if (unlikely(status == PP2_DESC_ERR_L4_CHECKSUM))
		return PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_BAD;

	RTE_LOG(ERR, PMD, "rx packet error: %d\n", status);

	/* return unknown state */
	return 0;
}

static uint16_t
mrvl_rx_pkt_burst(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct mrvl_rxq *q = rxq;
	struct pp2_ppio_desc descs[PP2_MAX_NUM_PUT_BUFFS];
	int i, ret;

	if (nb_pkts > PP2_MAX_NUM_PUT_BUFFS) {
		RTE_LOG(INFO, PMD, "Cannot recive %d packets in single burst\n",
			nb_pkts);
		nb_pkts = PP2_MAX_NUM_PUT_BUFFS;
	}

	ret = pp2_ppio_recv(q->priv->ppio, 0, q->queue_id, descs, &nb_pkts);
	if (ret < 0) {
		RTE_LOG(ERR, PMD, "Failed to receive packets\n");
		return 0;
	}

	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *mbuf;
		uint8_t l3_offset, l4_offset;

		mbuf = (struct rte_mbuf *)pp2_ppio_inq_desc_get_cookie(&descs[i]);
		mbuf->data_off += MRVL_PKT_EFFEC_OFFS;
		mbuf->pkt_len = pp2_ppio_inq_desc_get_pkt_len(&descs[i]);
		mbuf->data_len = mbuf->pkt_len;
		mbuf->port = q->port_id;
		mbuf->packet_type = mrvl_desc_to_packet_type_and_offset(&descs[i],
				&l3_offset, &l4_offset);
		mbuf->l2_len = l3_offset;
		mbuf->l3_len = l4_offset - l3_offset;

		if (likely(q->cksum_enabled))
			mbuf->ol_flags = mrvl_desc_to_ol_flags(&descs[i]);

		rx_pkts[i] = mbuf;

		q->num_missing++;
	}

	while (q->num_missing) {
		ret = mrvl_fill_bpool(q);
		if (ret)
			break;

		q->num_missing--;
	}

	return nb_pkts;
}

static int
mrvl_prepare_proto_info(uint64_t ol_flags, enum pp2_outq_l3_type *l3_type,
			enum pp2_outq_l4_type *l4_type, int *gen_l3_cksum,
			int *gen_l4_cksum)
{
	if (ol_flags & PKT_TX_IPV4) {
		*l3_type = PP2_OUTQ_L3_TYPE_IPV4;
		*gen_l3_cksum = ol_flags & PKT_TX_IP_CKSUM ? 1 : 0;
	} else if (ol_flags & PKT_TX_IPV6) {
		*l3_type = PP2_OUTQ_L3_TYPE_IPV6;
		*gen_l3_cksum = 0;
	} else {
		return -1;
	}

	ol_flags &= PKT_TX_L4_MASK;
	if (ol_flags == PKT_TX_TCP_CKSUM) {
		*l4_type = PP2_OUTQ_L4_TYPE_TCP;
		*gen_l4_cksum = 1;
	} else if (ol_flags == PKT_TX_UDP_CKSUM) {
		*l4_type = PP2_OUTQ_L4_TYPE_UDP;
		*gen_l4_cksum = 1;
	} else {
		*l4_type = PP2_OUTQ_L4_TYPE_OTHER;
		*gen_l4_cksum = 0;
	}

	return 0;
}

static uint16_t
mrvl_tx_pkt_burst(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct mrvl_txq *q = txq;
	struct pp2_ppio_desc descs[PP2_MAX_NUM_PUT_BUFFS];
	int i, ret;

	if (nb_pkts > PP2_MAX_NUM_PUT_BUFFS) {
		RTE_LOG(INFO, PMD, "Cannot send %d packets in single burst\n",
			nb_pkts);
		nb_pkts = PP2_MAX_NUM_PUT_BUFFS;
	}

	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *mbuf = tx_pkts[i];
		int gen_l3_cksum, gen_l4_cksum;
		enum pp2_outq_l3_type l3_type;
		enum pp2_outq_l4_type l4_type;

		pp2_ppio_outq_desc_reset(&descs[i]);
		pp2_ppio_outq_desc_set_phys_addr(&descs[i],
						 rte_pktmbuf_mtophys(mbuf));
		pp2_ppio_outq_desc_set_pkt_offset(&descs[i], 0);
		pp2_ppio_outq_desc_set_pkt_len(&descs[i],
					       rte_pktmbuf_pkt_len(mbuf));

		ret = mrvl_prepare_proto_info(mbuf->ol_flags, &l3_type,
					      &l4_type, &gen_l3_cksum,
					      &gen_l4_cksum);
		if (ret)
			continue;

		pp2_ppio_outq_desc_set_proto_info(&descs[i], l3_type, l4_type,
						  mbuf->l2_len,
						  mbuf->l2_len + mbuf->l3_len,
						  gen_l3_cksum, gen_l4_cksum);
	}

	ret = pp2_ppio_send(q->priv->ppio, q->priv->hif, 0, descs, &nb_pkts);
	if (ret)
		nb_pkts = 0;

	for (i = 0; i < nb_pkts; i++)
		rte_pktmbuf_free(tx_pkts[i]);

	return nb_pkts;
}

static int
mrvl_init_pp2(void)
{
	const char *const cpn_nodes[] = { "cpn-110-master", "cpn-110-slave" };
	const char *path = "/proc/device-tree/%s/config-space/ppv22@000000/" \
			   "eth%d@0%d0000/status";
	struct pp2_init_params init_params;
	int i, j, ret, len, fd;
	char buf[256];

	memset(&init_params, 0, sizeof(init_params));
	init_params.hif_reserved_map = MRVL_MUSDK_HIFS_RESERVED;
	init_params.bm_pool_reserved_map = MRVL_MUSDK_BPOOLS_RESERVED;

	for (i = 0; i < pp2_get_num_inst() && i < RTE_DIM(cpn_nodes); i++) {
		for (j = 0; j < PP2_NUM_ETH_PPIO; j++) {
			snprintf(buf, sizeof(buf), path, cpn_nodes[i], j, j + 1);

			fd = open(buf, O_RDONLY);
			if (fd < 0) {
				RTE_LOG(WARNING, PMD, "Failed to read %s\n", buf);
				continue;
			}

			len = lseek(fd, 0, SEEK_END);
			lseek(fd, 0, SEEK_SET);

			read(fd, buf, len);
			buf[len] = '\0';

			if (!strcmp(buf, "non-kernel")) {
				init_params.ppios[i][j].is_enabled = 1;
				init_params.ppios[i][j].first_inq = 0;
			}

			close(fd);
		}
	}

	return pp2_init(&init_params);
}

static void
mrvl_deinit_pp2(void)
{
	pp2_deinit();
}

static struct mrvl_priv *
mrvl_priv_create(const char *dev_name)
{
	struct pp2_bpool_params bpool_params;
	struct pp2_hif_params hif_params;
	char match[MRVL_MATCH_LEN];
	struct mrvl_priv *priv;
	int ret;

	priv = rte_zmalloc_socket(dev_name, sizeof(*priv), 0, rte_socket_id());
	if (!priv)
		return NULL;

	ret = pp2_netdev_get_port_info(dev_name, &priv->pp_id, &priv->ppio_id);
	if (ret)
		goto out_free_priv;

	priv->bpool_bit = mrvl_reserve_bit(&used_bpools[priv->pp_id],
					   PP2_BPOOL_NUM_POOLS);
	if (priv->bpool_bit < 0)
		goto out_free_priv;

	snprintf(match, sizeof(match), "pool-%d:%d", priv->pp_id, priv->bpool_bit);
	memset(&bpool_params, 0, sizeof(bpool_params));
	bpool_params.match = match;
	bpool_params.buff_len = RTE_MBUF_DEFAULT_BUF_SIZE;
	ret = pp2_bpool_init(&bpool_params, &priv->bpool);
	if (ret)
		goto out_clear_bpool_bit;

	priv->hif_bit = mrvl_reserve_bit(&used_hifs, MRVL_MUSDK_HIFS_MAX);
	if (priv->hif_bit < 0)
		goto out_deinit_bpool;

	snprintf(match, sizeof(match), "hif-%d", priv->hif_bit);
	memset(&hif_params, 0, sizeof(hif_params));
	hif_params.match = match;
	hif_params.out_size = MRVL_PP2_AGGR_TXQD_MAX;
	ret = pp2_hif_init(&hif_params, &priv->hif);
	if (ret)
		goto out_deinit_hif;

	priv->dma_addr_high = -1;
	priv->ppio_params.type = PP2_PPIO_T_NIC;
	priv->ppio_params.inqs_params.num_tcs = 1;
	priv->ppio_params.inqs_params.tcs_params[0].pkt_offset = MRVL_PKT_OFFS;
	priv->ppio_params.inqs_params.tcs_params[0].pools[0] = priv->bpool;

	return priv;
out_deinit_hif:
	pp2_hif_deinit(priv->hif);
	used_hifs &= ~(1 << priv->hif_bit);
out_deinit_bpool:
	pp2_bpool_deinit(priv->bpool);
out_clear_bpool_bit:
	used_bpools[priv->pp_id] &= ~(1 << priv->bpool_bit);
out_free_priv:
	rte_free(priv);
	return NULL;
}

static int
mrvl_eth_dev_create(const char *drv_name, const char *name)
{
	int ret, fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct rte_eth_dev *eth_dev;
	struct mrvl_priv *priv;
	struct ifreq req;

	eth_dev = rte_eth_dev_allocate(name);
	if (!eth_dev)
		return -ENOMEM;

	priv = mrvl_priv_create(name);
	if (!priv) {
		ret = -ENOMEM;
		goto out_free_dev;
	}

	eth_dev->data->mac_addrs = rte_zmalloc("mac_addrs",
			ETHER_ADDR_LEN * MRVL_MAC_ADDRS_MAX, 0);
	if (!eth_dev->data->mac_addrs) {
		RTE_LOG(ERR, PMD, "Failed to allocate space for eth addrs\n");
		ret = -ENOMEM;
		goto out_free_priv;
	}

	/* TODO: temporary solution until musdk provides something similar */
	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, name);
	ret = ioctl(fd, SIOCGIFHWADDR, &req);
	if (ret)
		goto out_free_mac;

	memcpy(eth_dev->data->mac_addrs[0].addr_bytes,
	       req.ifr_addr.sa_data, ETHER_ADDR_LEN);

	eth_dev->rx_pkt_burst = mrvl_rx_pkt_burst;
	eth_dev->tx_pkt_burst = mrvl_tx_pkt_burst;
	eth_dev->data->drv_name = drv_name;
	eth_dev->data->dev_private = priv;
	eth_dev->dev_ops = &mrvl_ops;

	return 0;
out_free_mac:
	rte_free(eth_dev->data->mac_addrs);
out_free_dev:
	rte_eth_dev_release_port(eth_dev);
out_free_priv:
	rte_free(priv);

	return ret;
}

static void
mrvl_eth_dev_destroy(const char *name)
{
	struct rte_eth_dev *eth_dev;
	struct mrvl_priv *priv;
	int i;

	eth_dev = rte_eth_dev_allocated(name);
	if (!eth_dev)
		return;

	priv = eth_dev->data->dev_private;
	/* TODO: cleanup priv before freeing? */
	rte_free(priv);
	rte_free(eth_dev->data->mac_addrs);
	rte_eth_dev_release_port(eth_dev);
}

static int
mrvl_get_ifnames(const char *key __rte_unused, const char *value, void *extra_args)
{
	static int n;
	const char **ifnames = extra_args;

	ifnames[n++] = value;

	return 0;
}

static int
rte_pmd_mrvl_probe(const char *name, const char *params)
{
	struct rte_kvargs *kvlist;
	const char *ifnames[PP2_NUM_ETH_PPIO * PP2_NUM_PKT_PROC];
	int i, n, ret;

	if (!name && !params)
		return -EINVAL;

	kvlist = rte_kvargs_parse(params, valid_args);
	if (!kvlist)
		return -EINVAL;

	n = rte_kvargs_count(kvlist, MRVL_IFACE_NAME_ARG);
	if (n > RTE_DIM(ifnames)) {
		ret = -EINVAL;
		goto out_free_kvlist;
	}

	rte_kvargs_process(kvlist, MRVL_IFACE_NAME_ARG,
			   mrvl_get_ifnames, &ifnames);

	ret = mv_sys_dma_mem_init(RTE_MRVL_MUSDK_DMA_MEMSIZE);
	if (ret)
		goto out_free_kvlist;

	ret = mrvl_init_pp2();
	if (ret)
		goto out_deinit_dma;

	for (i = 0; i < n; i++) {
		RTE_LOG(INFO, PMD, "Creating %s\n", ifnames[i]);
		ret = mrvl_eth_dev_create(name, ifnames[i]);
		if (ret)
			goto out_cleanup;
	}

	rte_kvargs_free(kvlist);

	return 0;
out_cleanup:
	for (; i >= 0; i--)
		mrvl_eth_dev_destroy(ifnames[i]);
out_deinit_pp2:
	mrvl_deinit_pp2();
out_deinit_dma:
	mv_sys_dma_mem_destroy();
out_free_kvlist:
	rte_kvargs_free(kvlist);

	return ret;
}

static int
rte_pmd_mrvl_remove(const char *name)
{
	int i;

	if (!name)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Removing %s\n", name);

	for (i = 0; i < rte_eth_dev_count(); i++) {
		char ifname[RTE_ETH_NAME_MAX_LEN];

		rte_eth_dev_get_name_by_port(i, ifname);
		mrvl_eth_dev_destroy(ifname);
	}

	mrvl_deinit_pp2();
	mv_sys_dma_mem_destroy();

	return 0;
}

static struct rte_vdev_driver pmd_mrvl_drv = {
	.probe = rte_pmd_mrvl_probe,
	.remove = rte_pmd_mrvl_remove,
};

RTE_PMD_REGISTER_VDEV(net_mrvl, pmd_mrvl_drv);
RTE_PMD_REGISTER_ALIAS(net_mrvl, hif);
