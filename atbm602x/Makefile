#
#makefile for build atbm_wifi.ko
#
###############################################################################
#
# when release to customer ,the CUSTOMER_SUPPORT_USED must set to y!!!!!!!!!!!!!
#
###############################################################################
CUSTOMER_SUPPORT_USED=y
###############################################################################
#PLATFORM_MTK_9255 22
###############################################################################

export
platform ?= PLATFORM_DEFAULT
ATBM_WIFI__EXT_CCFLAGS = -DATBM_WIFI_PLATFORM=24
#Android
#Linux
sys ?= Android
#arch:arm or arm64 or mips(NVT98517)
ARCH ?= arm
#export 
#ATBM_WIFI__EXT_CCFLAGS = -DATBM_WIFI_PLATFORM=$(platform)

ifeq ($(CUSTOMER_SUPPORT_USED),y)
    MAKEFILE_SUB ?= Makefile.build.customer
else
    MAKEFILE_SUB ?= Makefile.build
endif

ifeq ($(platform),)
    platform ?= PLATFORM_DEFAULT
endif

ifeq ($(KERNELRELEASE),)
    export DRIVER_PATH ?= $(shell pwd)

########################################PLATFORM_DEFAULT###########################
    ifeq ($(platform),PLATFORM_DEFAULT)
        KERDIR ?=
        CROSS_COMPILE ?=
        export
        ARCH ?= 
        ATBM_WIFI__EXT_CCFLAGS = -DATBM_WIFI_PLATFORM=24
    endif
###################################### END ########################################

    ifeq ($(platform),PLATFORM_AMLOGIC_920)
        KERDIR ?=
        CROSS_COMPILE ?=
        export
        ARCH ?= 
        ATBM_WIFI__EXT_CCFLAGS = -DATBM_WIFI_PLATFORM=24
    endif

    all:install

    install:
	    @echo "make PLATFORM_CROSS=$(platform)"
	    $(MAKE) all -f $(MAKEFILE_SUB) ARCH=$(ARCH)  CROSS_COMPILE=$(CROSS_COMPILE) KDIR=$(KERDIR) SYS=$(sys) PLAT=$(platform) -j8
    clean:
	    $(MAKE) -f $(MAKEFILE_SUB) KDIR=$(KERDIR) ARCH=$(ARCH) clean
    strip:
	    $(MAKE) -f $(MAKEFILE_SUB) KDIR=$(KERDIR) ARCH=$(ARCH) SYS=$(sys) PLAT=$(platform) strip
    get_ver:
	    $(MAKE) -f $(MAKEFILE_SUB) KDIR=$(KERDIR) ARCH=$(ARCH) SYS=$(sys) PLAT=$(platform) get_ver
    buid_config:
        #@rm -rf ./.config
	    $(MAKE) -C atbm_kconf clean
	    $(MAKE) -C atbm_kconf mconf -f Makefile
    menuconfig:buid_config
	    @./atbm_kconf/mconf ./atbm_kconf/Kconfig
else
    ifeq ($(platform),PLATFORM_DEFAULT)
        export
        ATBM_WIFI__EXT_CCFLAGS = -DATBM_WIFI_PLATFORM=0
    endif
    ifeq ($(platform),PLATFORM_AMLOGIC_920)
        export
        ATBM_WIFI__EXT_CCFLAGS = -DATBM_WIFI_PLATFORM=24
    endif
    export
    include $(src)/Makefile.build.kernel
endif

