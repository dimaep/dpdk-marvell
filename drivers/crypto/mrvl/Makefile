#
#  Copyright (c) 2017 Semihalf.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2 Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  SUCH DAMAGE.
#

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),config)
ifeq ($(LIBMUSDK_PATH),)
$(error "Please define LIBMUSDK_PATH environment variable")
endif
endif
endif

# library name
LIB = librte_pmd_mrvl_crypto.a

# build flags
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

# library version
LIBABIVER := 1

# versioning export map
EXPORT_MAP := rte_mrvl_pmd_version.map

# external library dependencies
CFLAGS += -I$(LIBMUSDK_PATH)/include
CFLAGS += -I$(LIBMUSDK_PATH)/include/drivers
CFLAGS += -DMVCONF_ARCH_DMA_ADDR_T_64BIT
LDLIBS += -L$(LIBMUSDK_PATH)/lib -lmusdk

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += rte_mrvl_pmd.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += rte_mrvl_pmd_ops.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += rte_mrvl_hmac.c

# library dependencies
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += lib/librte_eal
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += lib/librte_mempool
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += lib/librte_ring
DEPDIRS-$(CONFIG_RTE_LIBRTE_PMD_MRVL_CRYPTO) += lib/librte_cryptodev

include $(RTE_SDK)/mk/rte.lib.mk
