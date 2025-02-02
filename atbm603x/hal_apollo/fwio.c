/*
 * Firmware I/O code for mac80211 altobeam APOLLO drivers
 * *
 * Copyright (c) 2016, altobeam
 * Author:
 *
 * Based on apollo code
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@stericsson.com>
 *
 * Based on:
 * ST-Ericsson UMAC CW1200 driver which is
 * Copyright (c) 2010, ST-Ericsson
 * Author: Ajitpal Singh <ajitpal.singh@stericsson.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/debugfs.h>


#include "apollo.h"
#include "fwio.h"
#include "hwio.h"
#include "sbus.h"
#include "debug.h"
#include "bh.h"
#include "dcxo_dpll.h"

#ifdef ATBM_USE_SAVED_FW
#pragma message("Suspend Save Firmware")
#endif
#ifdef CONFIG_USE_FW_H
#pragma message("Use Firmware.h")
#endif
static char *fw = FIRMWARE_DEFAULT_PATH;


#if 0
module_param(fw, charp, 0644);
MODULE_PARM_DESC(fw, "Override platform_data firmware file");
#endif
#pragma message(FIRMWARE_DEFAULT_PATH)




static struct firmware_altobeam atbm_fw;
extern int atbm_wifi_chip_probe_get(void);
extern int atbm_wifi_bt_comb_get(void);
//extern void atbm_wifi_bt_comb_set(int status);

void atbm_release_firmware(void)
{
	if(atbm_fw.fw_dccm)
	{
		vfree(atbm_fw.fw_dccm);
		atbm_fw.fw_dccm = NULL;
	}
	if(atbm_fw.fw_iccm)
	{
		vfree(atbm_fw.fw_iccm);
		atbm_fw.fw_iccm = NULL;
	}
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
#ifdef CONFIG_USE_FW_H

	if(atbm_wifi_bt_comb_get() == 1){
#endif
		if(atbm_fw.fw_sram)
		{
			vfree(atbm_fw.fw_sram);
			atbm_fw.fw_sram = NULL;
		}
#ifdef CONFIG_USE_FW_H

	}
#endif
#endif
}
int atbm_init_firmware(void)
{
	memset(&atbm_fw,0,sizeof(struct firmware_altobeam));
	return 0;
}

int atbm_set_firmare(struct firmware_altobeam *fw)
{
#ifdef ATBM_USE_SAVED_FW
	if(!fw || (!fw->fw_dccm&&!fw->fw_iccm))
	{
		atbm_printk_err(KERN_ERR "fw is err\n");
		return -1;
	}

	if(atbm_fw.fw_dccm || atbm_fw.fw_iccm)
	{
		atbm_printk_err("atbm_fw has been set\n");
		return -1;
	}
	memcpy(&atbm_fw.hdr,&fw->hdr,sizeof(struct firmware_headr));
	
	if(atbm_fw.hdr.iccm_len)
	{
		atbm_fw.fw_iccm = vmalloc(atbm_fw.hdr.iccm_len);
		atbm_printk_err("%s:fw_iccm(%p)\n",__func__,atbm_fw.fw_iccm);
		if(!atbm_fw.fw_iccm)
		{
			atbm_printk_err("alloc atbm_fw.fw_iccm err\n");
			goto err;
		}
		memcpy(atbm_fw.fw_iccm,fw->fw_iccm,atbm_fw.hdr.iccm_len);
	}

	if(atbm_fw.hdr.dccm_len)
	{
		atbm_fw.fw_dccm= vmalloc(atbm_fw.hdr.dccm_len);
		
		atbm_printk_err("%s:fw_dccm(%p)\n",__func__,atbm_fw.fw_dccm);
		if(!atbm_fw.fw_dccm)
		{
			atbm_printk_err("alloc atbm_fw.fw_dccm err\n");
			goto err;
		}
		memcpy(atbm_fw.fw_dccm,fw->fw_dccm,atbm_fw.hdr.dccm_len);
	}
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
	if(atbm_wifi_bt_comb_get() == 1){

		if(atbm_fw.hdr.sram_len){
			atbm_fw.fw_sram = vmalloc(atbm_fw.hdr.sram_len);
			
			atbm_printk_err("%s:fw_sram(%p)\n",__func__,atbm_fw.fw_sram);
			if(!atbm_fw.fw_sram)
			{
				atbm_printk_err("alloc atbm_fw.fw_sram err\n");
				goto err;
			}
			memcpy(atbm_fw.fw_sram,fw->fw_sram,atbm_fw.hdr.sram_len);
		}
	}
#endif

	return 0;
err:
	if(atbm_fw.fw_iccm)
	{
		vfree(atbm_fw.fw_iccm);
		atbm_fw.fw_iccm = NULL;
	}

	if(atbm_fw.fw_dccm)
	{
		vfree(atbm_fw.fw_dccm);
		atbm_fw.fw_dccm = NULL;
	}
	
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
	if(atbm_wifi_bt_comb_get() == 1){

		if(atbm_fw.fw_sram)
		{
			vfree(atbm_fw.fw_sram);
			atbm_fw.fw_sram = NULL;
		}
	}
#endif

#endif //#ifndef USB_BUS
	return -1;
}

#define FW_IS_READY	((atbm_fw.fw_dccm != NULL) || (atbm_fw.fw_iccm != NULL))
int atbm_get_fw(struct firmware_altobeam *fw)
{
	if(!FW_IS_READY)
	{
		return -1;
	}

	memcpy(&fw->hdr,&atbm_fw.hdr,sizeof(struct firmware_headr));
	fw->fw_iccm = atbm_fw.fw_iccm;
	fw->fw_dccm = atbm_fw.fw_dccm;
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
	if(atbm_wifi_bt_comb_get() == 1)
		fw->fw_sram = atbm_fw.fw_sram;
#endif
	return 0;
}


int atbm_get_hw_type(u32 config_reg_val, int *major_revision)
{
#if 0
	int hw_type = -1;
	u32 config_value = config_reg_val;
	//u32 silicon_type = (config_reg_val >> 24) & 0x3;
	u32 silicon_vers = (config_reg_val >> 31) & 0x1;

	/* Check if we have CW1200 or STLC9000 */

	hw_type = HIF_1601_CHIP;
#endif
	return HIF_1601_CHIP;
}

static int atbm_load_firmware_generic(struct atbm_common *priv, u8 *data,u32 size,u32 addr)
{

	int ret=0;
	u32 put = 0;
	u8 *buf = NULL;


	buf = atbm_kmalloc(DOWNLOAD_BLOCK_SIZE*2, GFP_KERNEL | GFP_DMA);
	if (!buf) {
		atbm_dbg(ATBM_APOLLO_DBG_ERROR,
			"%s: can't allocate bootloader buffer.\n", __func__);
		ret = -ENOMEM;
		goto error;
	}
	
#ifndef HW_DOWN_FW
	if(priv->sbus_ops->bootloader_debug_config)
		priv->sbus_ops->bootloader_debug_config(priv->sbus_priv,0);
#endif //#ifndef HW_DOWN_FW

	/*  downloading loop */
	atbm_printk_init( "%s: addr %x: len %x\n",__func__,addr,size);
	for (put = 0; put < size ;put += DOWNLOAD_BLOCK_SIZE) {
		u32 tx_size;


		/* calculate the block size */
		tx_size  = min((size - put),(u32)DOWNLOAD_BLOCK_SIZE);

		memcpy(buf, &data[put], tx_size);

		/* send the block to sram */
		ret = atbm_fw_write(priv,put+addr,buf, tx_size);
		if (ret < 0) {
			atbm_dbg(ATBM_APOLLO_DBG_ERROR,
				"%s: can't write block at line %d.\n",
				__func__, __LINE__);
			goto error;
		}
	} /* End of bootloader download loop */

error:
	atbm_kfree(buf);
	return ret;


}
void  atbm_efuse_read_byte(struct atbm_common *priv,u32 byteIndex, u32 *value)
{
	//HW_WRITE_REG(0x16b00000, (byteIndex<<8));
	//*value = HW_READ_REG(0x16b00004);	
	
	atbm_direct_write_reg_32(priv,0x16b00000, (byteIndex<<8));
	atbm_direct_read_reg_32(priv,0x16b00004,value);
}

u32 atbm_efuse_read_bit(struct atbm_common *priv,u32 bitIndex)
{
	u32	efuseBitIndex = bitIndex;
	u32 byteIndex;
	u32 value = 0;

	{
		byteIndex = efuseBitIndex / 8;
		atbm_efuse_read_byte(priv,byteIndex, &value);
	}
	value = value >> (efuseBitIndex % 8);
	value &= 0x1;
	return value;
}
extern void atbm_wifi_chip_probe_set(u16 idProduct);

bool atbm_check_aresLite_type(struct atbm_common *priv)
{
//	
	
		
#ifdef USB_BUS
	if(atbm_wifi_chip_probe_get() == 2){
		priv->aresLite_flag = true;
		if ((atbm_efuse_read_bit(priv,8) == 1) && (atbm_efuse_read_bit(priv,10) == 1))
		{
			if(atbm_efuse_read_bit(priv,3) == 1){
				atbm_printk_err("Get 6012B-Y UID Success!!Not support BLE\n");
				priv->chip_aresLite = 1;//0:6032-X/6031-X  1:6012B-Y  2:6012B-X
			}else{
				atbm_printk_err("Get 6012B-X UID Success!!support BLE\n");
				priv->chip_aresLite = 2;
			}
			priv->chip_version = ARES_6012B;
		}else if((atbm_efuse_read_bit(priv,8) == 0) && 
				(atbm_efuse_read_bit(priv,9) == 0) &&
				(atbm_efuse_read_bit(priv,10) == 0)){
			atbm_printk_err("Get 6032-X UID Success!!support BLE\n");
			priv->chip_aresLite = 0;
		}else{
			atbm_printk_err("Get UID fail!!!! default use 6032-X UID !!support BLE\n");
			priv->chip_aresLite = 0;
		}
	}else if(atbm_wifi_chip_probe_get() == 1){
		priv->aresLite_flag = false;
		if ((atbm_efuse_read_bit(priv,152) == 1) && (atbm_efuse_read_bit(priv,154) == 1)){
			
			priv->chip_aresLite = 0;
			atbm_printk_err("Get 6012B UID Success!!\n");
			priv->chip_version = ARES_6012B;
		}

	}
#else 
		if (atbm_efuse_read_bit(priv,9) == 1){
			atbm_wifi_chip_probe_set(0x888b);
			priv->aresLite_flag = true;
			atbm_printk_err("Get 6031-X UID Success!!support BLE\n");
			priv->chip_aresLite = 0;
		}else{
			atbm_wifi_chip_probe_set(0x8888);
			atbm_printk_err("Get UID fail!!!! default use 6031  !!\n");
			priv->chip_aresLite = 0;
			priv->aresLite_flag = false;
		}
#endif
	
	return 0;
}

bool atbm_check_6012B(struct atbm_common *priv)
{
	if ((atbm_efuse_read_bit(priv,152) == 1) && (atbm_efuse_read_bit(priv,154) == 1))
	{
		printk("Get 6012B UID Success!!\n");
		return 1;
	}
	return 0;
}


void  atbm_get_chiptype(struct atbm_common *hw_priv)
{
	u32 chipver = 0;

	atbm_direct_read_reg_32(hw_priv,0x0acc017c,&chipver);
    chipver&=0xff;
	
	hw_priv->chip_version = ARES_B;
	switch(chipver)
	{
		case 0x14:	
			hw_priv->chip_version = APOLLO_F;	
			break;
		case 0x24:	
		case 0x25:	
			//strHwChipFw = ("AthenaB.bin");
			hw_priv->chip_version = ATHENA_B;
			break;
		case 0x45:	
		case 0x46:	
		case 0x47:	
			hw_priv->chip_version = ARES_A;
			break;	
		case 0x49:
			hw_priv->chip_version = ARES_B;	
			atbm_check_aresLite_type(hw_priv);
			//if(atbm_check_6012B(hw_priv))
				//hw_priv->chip_version = ARES_6012B;
			break;
		case 0x4a:
			hw_priv->chip_version = ARES_LITE;	
			atbm_check_aresLite_type(hw_priv);
			break;
		case 0x64:
		case 0x65:
			hw_priv->chip_version = HERA;		
			break;
		default:
			//g_wifi_chip_type = ATHENA_B;
			atbm_printk_always("%s, <ERROR> cannot read chip id\n",__func__ );
		
		break;
	}

	atbm_printk_always("%s, chipver=0x%x, g_wifi_chip_type[%d]\n",__func__, chipver,hw_priv->chip_version );
}

char * atbm_HwGetChipFw(struct atbm_common *priv)
{
#if 0
	u32 chipver = 0;
#endif
	char * strHwChipFw = NULL;

	if(fw)
	{
		atbm_printk_always("fw [%s]\n", fw );
	 	return fw;
	}

#if 0
	atbm_direct_read_reg_32(priv,0x0acc017c,&chipver);
	
	switch(chipver)
	{
		case 0x0:	
			strHwChipFw = ("ApolloC0.bin");		
			break;
		case 0x1:	
			strHwChipFw = ("ApolloC0_TC.bin");	
			break;
		case 0x3:	
			strHwChipFw = ("ApolloC1_TC.bin");	
			break;
		case 0xc:	
			strHwChipFw = ("ApolloD.bin");		
			break;
		case 0xd:	
			strHwChipFw = ("ApolloD_TC.bin");	
			break;
		case 0x10:	
			strHwChipFw = ("ApolloE.bin");		
			break;
		case 0x20:	
			strHwChipFw = ("AthenaA.bin");		
			break;
		case 0x14:	
			strHwChipFw = ("ApolloF.bin");		
			break;
		case 0x15:	
			strHwChipFw = ("ApolloF_TC.bin");	
			break;
		case 0x24:	
			strHwChipFw = ("AthenaB.bin");		
			break;
		case 0x25:	
			strHwChipFw = ("AthenaBX.bin");		
			break;
		case 0x18:	
			strHwChipFw = ("Apollo_FM.bin");		
			break;
		default:
			strHwChipFw = FIRMWARE_DEFAULT_PATH;		
		break;
	}

	atbm_printk_always("%s, chipver=0x%x, use fw [%s]\n",__func__, chipver,strHwChipFw );
#endif
	return strHwChipFw;
}

//#define TEST_DCXO_CONFIG move to makefile
#ifndef CONFIG_USE_FW_H
#define USED_FW_FILE
#endif
#ifdef USED_FW_FILE
/*check if fw headr ok*/
static int atbm_fw_checksum(struct firmware_headr * hdr)
{
	return 1;
}
#if 0
//#else
#ifdef USB_BUS
#include "firmware_usb.h"
#endif
#ifdef SDIO_BUS
#include "firmware_sdio.h"
#endif
#ifdef SPI_BUS
#include "firmware_spi.h"
#endif

#endif


#endif
#ifdef CONFIG_PM_SLEEP
#pragma message("CONFIG_PM_SLEEP")
int atbm_cache_fw_before_suspend(struct device	 *pdev)
{
#if defined (USED_FW_FILE) && defined(ATBM_USE_SAVED_FW)
	int ret = 0;
	const char *fw_path= fw;
	const struct firmware *firmware = NULL;
	struct firmware_altobeam fw_altobeam;

	memset(&fw_altobeam,0,sizeof(struct firmware_altobeam));
	if(fw_path == NULL){
		goto error2;
	}
	if(FW_IS_READY){
		atbm_printk_err("atbm_fw ready\n");
		goto error2;
	}
	
	ret = request_firmware(&firmware, fw_path, pdev);
	if(ret){
		atbm_printk_err("request_firmware err\n");
		goto error2;
	}
	if(*(int *)firmware->data == ALTOBEAM_WIFI_HDR_FLAG){
		memcpy(&fw_altobeam.hdr,firmware->data,sizeof(struct firmware_headr));
		if(atbm_fw_checksum(&fw_altobeam.hdr)==0){
			ret = -1;
			 atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: atbm_fw_checksum fail 11\n", __func__);
			 goto error1;
		}
		fw_altobeam.fw_iccm = (u8 *)firmware->data + sizeof(struct firmware_headr);
		fw_altobeam.fw_dccm = fw_altobeam.fw_iccm + fw_altobeam.hdr.iccm_len;
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
		if(atbm_wifi_bt_comb_get() == 1)
			fw_altobeam.fw_sram = fw_altobeam.fw_dccm + fw_altobeam.hdr.dccm_len;
#endif
		atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: have header,lmac version(%d) iccm_len(%d) dccm_len(%d)\n", __func__,
			fw_altobeam.hdr.version,fw_altobeam.hdr.iccm_len,fw_altobeam.hdr.dccm_len);
	}
	else {
		fw_altobeam.hdr.version =  0x001;
		if(firmware->size > DOWNLOAD_ITCM_SIZE){
			fw_altobeam.hdr.iccm_len =  DOWNLOAD_ITCM_SIZE;
			fw_altobeam.hdr.dccm_len =  firmware->size - fw_altobeam.hdr.iccm_len;
			if(fw_altobeam.hdr.dccm_len > DOWNLOAD_DTCM_SIZE) {
				ret = -1;
			 	atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: atbm_fw_checksum fail 22\n", __func__);
			 	goto error1;
			}
			fw_altobeam.fw_iccm = (u8 *)firmware->data;
			fw_altobeam.fw_dccm = fw_altobeam.fw_iccm+fw_altobeam.hdr.iccm_len;
		}
		else {
			fw_altobeam.hdr.iccm_len = firmware->size;
			fw_altobeam.hdr.dccm_len = 0;
			fw_altobeam.fw_iccm = (u8 *)firmware->data;
			
		}

	}
	atbm_release_firmware();
	
	memcpy(&atbm_fw.hdr,&fw_altobeam.hdr,sizeof(struct firmware_headr));
	if(atbm_fw.hdr.iccm_len)
	{
		atbm_fw.fw_iccm = vmalloc(atbm_fw.hdr.iccm_len);
		
		if(!atbm_fw.fw_iccm)
		{
			atbm_printk_err( "alloc atbm_fw.fw_iccm err\n");
			goto error1;
		}
		memcpy(atbm_fw.fw_iccm,fw_altobeam.fw_iccm,atbm_fw.hdr.iccm_len);
	}

	if(atbm_fw.hdr.dccm_len)
	{
		atbm_fw.fw_dccm= vmalloc(atbm_fw.hdr.dccm_len);

		if(!atbm_fw.fw_dccm)
		{
			atbm_printk_err("alloc atbm_fw.fw_dccm err\n");
			goto error1;
		}
		memcpy(atbm_fw.fw_dccm,fw_altobeam.fw_dccm,atbm_fw.hdr.dccm_len);
	}
	
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
	if(atbm_wifi_bt_comb_get() == 1){

		if(atbm_fw.hdr.sram_len){
			atbm_fw.fw_sram = vmalloc(atbm_fw.hdr.sram_len);
			if(!atbm_fw.fw_sram)
			{
				atbm_printk_err("alloc atbm_fw.fw_dccm err\n");
				goto error1;
			}
			memcpy(atbm_fw.fw_sram,fw_altobeam.fw_sram,atbm_fw.hdr.sram_len);		
		}
	}
#endif
	
	atbm_printk_always("%s:cached fw\n",__func__);
	release_firmware(firmware);
	return 0;
error1:
	
	atbm_printk_err("%s:error1\n",__func__);
	release_firmware(firmware);
	if(atbm_fw.fw_iccm)
	{
		vfree(atbm_fw.fw_iccm);
		atbm_fw.fw_iccm = NULL;
	}

	if(atbm_fw.fw_dccm)
	{
		vfree(atbm_fw.fw_dccm);
		atbm_fw.fw_dccm = NULL;
	}
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
	if(atbm_wifi_bt_comb_get() == 1){

		if(atbm_fw.fw_sram)
		{
			vfree(atbm_fw.fw_sram);
			atbm_fw.fw_sram = NULL;		
		}
	}
#endif
error2:
	atbm_printk_err("%s:error2\n",__func__);
	return ret;
#else
	return 0;
#endif//
}
#endif
static int atbm_start_load_firmware(struct atbm_common *priv)
{

	int ret;
#ifdef USED_FW_FILE
	const char *fw_path= atbm_HwGetChipFw(priv);
#endif//
	const struct firmware *firmware = NULL;
	struct firmware_altobeam fw_altobeam;
#if ROM_BIN_TEST
	struct firmware_altobeam fw_rom;
	const struct firmware *rom_firmware = NULL;
#endif
	u32 ITCM_ADDR = 0;

	if(priv->chip_version >= ARES_A){
		ITCM_ADDR = 0x00010000;
	}else {
		ITCM_ADDR = 0x00000000;
	}
loadfw:
	//u32 testreg_uart;
#ifdef START_DCXO_CONFIG
	atbm_ahb_write_32(priv,0x18e00014,0x200);
	atbm_ahb_read_32(priv,0x18e00014,&val32_1);
	//atbm_ahb_read_32(priv,0x16400000,&testreg_uart);
	atbm_printk_always("0x18e000e4-->%08x %08x\n",val32_1);
#endif//TEST_DCXO_CONFIG
	if(!FW_IS_READY)
	{
#ifdef USED_FW_FILE
	    atbm_dbg(ATBM_APOLLO_DBG_MSG,"%s:FW FILE = %s\n",__func__,fw_path);
		ret = request_firmware(&firmware, fw_path, priv->pdev);
		if (ret) {
			atbm_dbg(ATBM_APOLLO_DBG_ERROR,
				"%s: can't load firmware file %s.\n",
				__func__, fw_path);
			goto error;
		}
		BUG_ON(!firmware->data);
		if ((*(int*)firmware->data == ALTOBEAM_WIFI_HDR_FLAG) || (*(int*)firmware->data == ALTOBEAM_WIFI_HDR_FLAG_V2))
		{
			memcpy(&fw_altobeam.hdr,firmware->data,sizeof(struct firmware_headr));
			if(atbm_fw_checksum(&fw_altobeam.hdr)==0){
				ret = -1;
				 atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: atbm_fw_checksum fail 11\n", __func__);
				 goto error;
			}
			fw_altobeam.fw_iccm = (u8 *)firmware->data + sizeof(struct firmware_headr);
			fw_altobeam.fw_dccm = fw_altobeam.fw_iccm + fw_altobeam.hdr.iccm_len;
			if(fw_altobeam.hdr.sram_len){
				fw_altobeam.fw_sram = fw_altobeam.fw_dccm + fw_altobeam.hdr.dccm_len;
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
				if (*(int*)firmware->data == ALTOBEAM_WIFI_HDR_FLAG)
					fw_altobeam.hdr.sram_addr = DOWNLOAD_BLE_SRAM_ADDR;
#endif
			}
			atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: have header,lmac version(%d) iccm_len(%d) dccm_len(%d),fwsize(%zu),hdrsize(%zu)\n", __func__,
				fw_altobeam.hdr.version,fw_altobeam.hdr.iccm_len,fw_altobeam.hdr.dccm_len,firmware->size,sizeof(struct firmware_headr));

			//frame_hexdump("fw_iccm ",fw_altobeam.fw_iccm,64);
			//frame_hexdump("fw_dccm ",fw_altobeam.fw_dccm,64);
		}
		else {
			fw_altobeam.hdr.version =  0x001;
			if(firmware->size > DOWNLOAD_ITCM_SIZE){
				fw_altobeam.hdr.iccm_len =  DOWNLOAD_ITCM_SIZE;
				fw_altobeam.hdr.dccm_len =  firmware->size - fw_altobeam.hdr.iccm_len;
				if(fw_altobeam.hdr.dccm_len > DOWNLOAD_DTCM_SIZE) {
					ret = -1;
				 	atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: atbm_fw_checksum fail 22\n", __func__);
				 	goto error;
				}
				fw_altobeam.fw_iccm = (u8 *)firmware->data;
				fw_altobeam.fw_dccm = fw_altobeam.fw_iccm+fw_altobeam.hdr.iccm_len;
			}
			else {
				fw_altobeam.hdr.iccm_len = firmware->size;
				fw_altobeam.hdr.dccm_len = 0;
				fw_altobeam.fw_iccm = (u8 *)firmware->data;
				
			}

		}

#if ROM_BIN_TEST
		atbm_dbg(ATBM_APOLLO_DBG_MSG,"%s:FW FILE = %s\n",__func__,"ROM.bin");
		ret = request_firmware(&rom_firmware, "ROM.bin", priv->pdev);
		if (ret) {
			atbm_dbg(ATBM_APOLLO_DBG_ERROR,
				"%s: can't load firmware file %s.\n",
				__func__, "ROM.bin");
			goto error;
		}
		BUG_ON(!rom_firmware->data);
		if(*(int *)rom_firmware->data == ALTOBEAM_WIFI_HDR_FLAG){
			memcpy(&fw_rom.hdr,rom_firmware->data,sizeof(struct firmware_headr));
			if(atbm_fw_checksum(&fw_rom.hdr)==0){
				ret = -1;
				 atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: atbm_fw_checksum fail 11\n", __func__);
				 goto error;
			}
			fw_rom.fw_iccm = (u8 *)rom_firmware->data + sizeof(struct firmware_headr);
			fw_rom.fw_dccm = fw_rom.fw_iccm + fw_rom.hdr.iccm_len;
			atbm_dbg(ATBM_APOLLO_DBG_ERROR,"%s: have header,lmac version(%d) iccm_len(%d) dccm_len(%d),fwsize(%zu),hdrsize(%zu)\n", __func__,
				fw_rom.hdr.version,fw_rom.hdr.iccm_len,fw_rom.hdr.dccm_len,rom_firmware->size,sizeof(struct firmware_headr));
		}
#endif

#else //USED_FW_FILE
		{
		//atbm_dbg(ATBM_APOLLO_DBG_ERROR,"used firmware.h=\n");
		if(atbm_wifi_chip_probe_get() == 2){
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
			if(atbm_wifi_bt_comb_get() == 1){
				ret = load_usb_wifi_bt_comb_firmware(&fw_altobeam);

			}else 
#endif
				ret = load_usb_wifi_Lite_firmware(&fw_altobeam);

			atbm_printk_err("\n======>>> load %s firmware <<<======\n\n",atbm_wifi_bt_comb_get()?"WIFI BLE COMB":"only WIFI");
		
		}
		else if(atbm_wifi_chip_probe_get() == 1){
			
			ret = load_usb_wifi_firmware(&fw_altobeam);
			
		}
		else{
			atbm_printk_err("WARNING!!!!!!not found firmware!! \n");
			goto error;
		}
		if(ret < 0){
			atbm_printk_err("!!!!! loader firmware ERROR!!!!!!! \n");
			goto error;
		}
		//atbm_wifi_bt_comb_set(priv->wifi_ble_comb);
#if 0		
		fw_altobeam.hdr.iccm_len = sizeof(fw_code);
		fw_altobeam.hdr.dccm_len = sizeof(fw_data);
#ifdef CONFIG_ATBM_BLE_CODE_SRAM
		fw_altobeam.hdr.sram_len = sizeof(fw_sram);
		fw_altobeam.fw_sram = &fw_sram[0];
#endif
		fw_altobeam.fw_iccm = &fw_code[0];
		fw_altobeam.fw_dccm = &fw_data[0];
#endif
		}
#endif //USED_FW_FILE
		atbm_set_firmare(&fw_altobeam);
#if ROM_BIN_TEST
		atbm_set_firmare(&fw_rom);
#endif
	}
	else
	{
		if((ret = atbm_get_fw(&fw_altobeam))<0)
		{
			goto error;
		}
#if ROM_BIN_TEST
		if((ret = atbm_get_fw(&fw_rom))<0)
		{
			goto error;
		}
#endif

	}
	atbm_dbg(ATBM_APOLLO_DBG_ERROR,"START DOWNLOAD ICCM=========\n");

	ret = atbm_load_firmware_generic(priv,fw_altobeam.fw_iccm,fw_altobeam.hdr.iccm_len,DOWNLOAD_ITCM_ADDR);
	if(ret<0)
		goto error;

#if ROM_BIN_TEST
	atbm_dbg(ATBM_APOLLO_DBG_ERROR,"START DOWNLOAD ICCM CODE=====\n");

	ret = atbm_load_firmware_generic(priv, fw_rom.fw_iccm, fw_rom.hdr.iccm_len,
		ITCM_ADDR + fw_altobeam.hdr.iccm_len);
	if (ret < 0)
		goto error;
#endif

	#ifdef USB_BUS
	//fw_altobeam.hdr.dccm_len = 0xd000;
	if (fw_altobeam.hdr.dccm_len > 0xa000)
	fw_altobeam.hdr.dccm_len = 0xa000;
	#else
	if(fw_altobeam.hdr.dccm_len > 0xa000)
	fw_altobeam.hdr.dccm_len = 0xa000;
	#endif			

	atbm_dbg(ATBM_APOLLO_DBG_ERROR,"START DOWNLOAD DCCM=========\n");
	ret = atbm_load_firmware_generic(priv,fw_altobeam.fw_dccm,fw_altobeam.hdr.dccm_len,DOWNLOAD_DTCM_ADDR);
	if(ret<0)
		goto error;

	if(fw_altobeam.hdr.sram_len){
		atbm_dbg(ATBM_APOLLO_DBG_ERROR,"START DOWNLOAD SRAM=========\n");
		ret = atbm_load_firmware_generic(priv, fw_altobeam.fw_sram, fw_altobeam.hdr.sram_len, fw_altobeam.hdr.sram_addr);
		if(ret<0)
			goto error;
	}

	atbm_dbg(ATBM_APOLLO_DBG_MSG, "FIRMWARE DOWNLOAD SUCCESS\n");

error:
	if (ret<0){
		if(atbm_reset_lmc_cpu(priv) == 0)
			goto loadfw;
	}
	if (firmware)
		release_firmware(firmware);
#if ROM_BIN_TEST
	if(rom_firmware){
		release_firmware(rom_firmware);
	}
#endif
	return ret;


}


int atbm_load_firmware(struct atbm_common *hw_priv)
{
	int ret = 0;
	
	atbm_get_chiptype(hw_priv);
	
	atbm_printk_init("atbm_before_load_firmware++\n");
	ret = atbm_before_load_firmware(hw_priv);
	if(ret <0)
		goto out;
	atbm_printk_init("atbm_start_load_firmware++\n");
	ret = atbm_start_load_firmware(hw_priv);
	if(ret <0)
		goto out;
	atbm_printk_init("atbm_after_load_firmware++\n");
	ret = atbm_after_load_firmware(hw_priv);
	if(ret <0){
		goto out;
	}
	ret =0;
out:
	return ret;

}

