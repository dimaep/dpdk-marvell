#   BSD LICENSE
#
#   Copyright(c) 2017 Semihalf. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Semihalf nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),config)
ifeq ($(LIBMUSDK_PATH),)
$(error "Please define LIBMUSDK_PATH environment variable")
endif
endif
endif

# library name
LIB = librte_pmd_mrvl.a

# library version
LIBABIVER := 1

# versioning export map
EXPORT_MAP := rte_pmd_mrvl_version.map

# external library dependencies
CFLAGS += -I$(LIBMUSDK_PATH)/include -DMVCONF_ARCH_DMA_ADDR_T_64BIT -DCONF_PP2_BPOOL_COOKIE_SIZE=64
LDLIBS += -L$(LIBMUSDK_PATH)/lib -lmusdk

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += mrvl_ethdev.c

# library dependencies
DEPDIRS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += lib/librte_eal
DEPDIRS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += lib/librte_ether
DEPDIRS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += lib/librte_mempool
DEPDIRS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += lib/librte_net
DEPDIRS-$(CONFIG_RTE_LIBRTE_MRVL_PMD) += lib/librte_kvargs

include $(RTE_SDK)/mk/rte.lib.mk
