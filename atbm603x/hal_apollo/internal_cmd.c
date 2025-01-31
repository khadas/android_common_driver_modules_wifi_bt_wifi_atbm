#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/dcache.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include "apollo.h"
#include "bh.h"
#include "hwio.h"
#include "wsm.h"
#include "sbus.h"
#include "debug.h"
#include "apollo_plat.h"
#include "sta.h"
#include "ap.h"
#include "scan.h"
#include "internal_cmd.h"
#include "svn_version.h"
#include "dev_ioctl.h"

extern struct atbm_common *g_hw_priv;
static struct atbm_gpio_config atbm_gpio_table[]=
{
	{
		.gpio = 4,
		.flags = 0,
		.fun_ctrl = {.base_addr	= 0x1740000C,.start_bit  = 0,.width		= 4,.val = 0,},
		.pup_ctrl = {.base_addr	= 0x1740000C,.start_bit  = 11,.width	= 1,.val = 0,},
		.pdu_ctrl = {.base_addr	= 0x1740000C,.start_bit  = 12,.width	= 1,.val = 0,},
		.dir_ctrl = {.base_addr	= 0x16800028,.start_bit  = 4,.width		= 1,.val = 0,},
		.out_val  = {.base_addr	= 0x16800024,.start_bit  = 4,.width		= 1,.val = 0,},
		.out_val  = {.base_addr	= 0x16800020,.start_bit  = 4,.width		= 1,.val = 0,},
	},
	{
		.gpio = 20,
		.flags = 0,
		.fun_ctrl = {.base_addr	= 0x1740002C,.start_bit  = 0,.width		= 4,.val = 0,},
		.pup_ctrl = {.base_addr	= 0x1740002C,.start_bit  = 11,.width	= 1,.val = 0,},
		.pdu_ctrl = {.base_addr	= 0x1740002C,.start_bit  = 12,.width	= 1,.val = 0,},
		.dir_ctrl = {.base_addr	= 0x16800028,.start_bit  = 20,.width	= 1,.val = 0,},
		.out_val  = {.base_addr	= 0x16800024,.start_bit  = 20,.width	= 1,.val = 0,},
		.in_val  = {.base_addr	= 0x16800020,.start_bit  = 20,.width	= 1,.val = 0,},
	},
	{
		.gpio = 21,
		.flags = 0,
		.fun_ctrl = {.base_addr	= 0x1740002C,.start_bit  = 16,.width	= 4,.val = 0,},
		.pup_ctrl = {.base_addr	= 0x1740002C,.start_bit  = 27,.width	= 1,.val = 0,},
		.pdu_ctrl = {.base_addr	= 0x1740002C,.start_bit  = 28,.width	= 1,.val = 0,},
		.dir_ctrl = {.base_addr	= 0x16800028,.start_bit  = 21,.width	= 1,.val = 0,},
		.out_val  = {.base_addr	= 0x16800024,.start_bit  = 21,.width	= 1,.val = 0,},
		.in_val  = {.base_addr	= 0x16800020,.start_bit  = 21,.width	= 1,.val = 0,},
	},
	{
		.gpio = 22,
		.flags = 0,
		.fun_ctrl = {.base_addr	= 0x17400030,.start_bit  = 0,.width		= 4,.val = 0,},
		.pup_ctrl = {.base_addr	= 0x17400030,.start_bit  = 11,.width	= 1,.val = 0,},
		.pdu_ctrl = {.base_addr	= 0x17400030,.start_bit  = 12,.width	= 1,.val = 0,},
		.dir_ctrl = {.base_addr	= 0x16800028,.start_bit  = 22,.width	= 1,.val = 0,},
		.out_val  = {.base_addr	= 0x16800024,.start_bit  = 22,.width	= 1,.val = 0,},
		.in_val  = {.base_addr	= 0x16800020,.start_bit  = 22,.width	= 1,.val = 0,},
	},
	{
		.gpio = 23,
		.flags = 0,
		.fun_ctrl = {.base_addr	= 0x17400030,.start_bit  = 16,.width	= 4,.val = 0,},
		.pup_ctrl = {.base_addr	= 0x17400030,.start_bit  = 27,.width	= 1,.val = 0,},
		.pdu_ctrl = {.base_addr	= 0x17400030,.start_bit  = 28,.width	= 1,.val = 0,},
		.dir_ctrl = {.base_addr	= 0x16800028,.start_bit  = 23,.width	= 1,.val = 0,},
		.out_val  = {.base_addr	= 0x16800024,.start_bit  = 23,.width	= 1,.val = 0,},
		.in_val  = {.base_addr	= 0x16800020,.start_bit  = 23,.width	= 1,.val = 0,},
	},
};

#define DCXO_TRIM_REG 0x1610100c //bit 5:0


#define ATBM_WSM_ADAPTIVE		"set_adaptive"ATBM_SPACE_STR
#define ATBM_WSM_TXPWR_DCXO		"set_txpwr_and_dcxo"ATBM_SPACE_STR
#define ATBM_WSM_TXPWR			"set_txpower"ATBM_SPACE_STR
#define ATBM_WSM_SET_FREQ		"set_freq"ATBM_SPACE_STR"%d"ATBM_SPACE_STR"%d"
#define ATBM_WSM_FIX_RATE		"lmac_rate"ATBM_SPACE_STR"%d"
#define ATBM_WSM_TOP_RATE		"lmac_max_rate"ATBM_SPACE_STR"%d"
#define ATBM_WSM_MIN_RATE		"lmac_min_rate"ATBM_SPACE_STR"%d"
#define ATBM_WSM_SET_RATE_POWER	"set_spec_rate_txpower_mode"ATBM_SPACE_STR"%d"ATBM_SPACE_STR"%d"

#ifdef CONFIG_ATBM_MONITOR_SPECIAL_MAC
#define ATBM_WSM_MONITOR_MAC	"set_sta_monitor"ATBM_SPACE_STR"%d"ATBM_SPACE_STR"%d"ATBM_SPACE_STR"%x,%x,%x,%x,%x,%x"
#endif
#define ATBM_WSM_CMD_LEN		1680
const char *chip_6038  = "6038";
const char *chip_6032  = "6032";
const char *chip_6032i = "6032i";
const char *chip_101B  = "101B";


unsigned int HW_READ_REG_BIT(unsigned int addr,int endbit,int startbit)
{	
	unsigned int regdata=0;
	unsigned int regmask=0;
	
	atbm_direct_read_reg_32(atbm_hw_priv_dereference(), addr, &regdata);

	regmask = ~((1<<startbit) -1);
	regmask &= ((1<<endbit) -1)|(1<<endbit);
	regdata &= regmask;
	regdata >>=  startbit;
	
	return regdata;
}

void HW_WRITE_REG_BIT(unsigned int addr,unsigned int endBit,unsigned int startBit,unsigned int data )
{
	unsigned int	uiRegValue=0;
	unsigned int  regmask=0;
		
	atbm_direct_read_reg_32(atbm_hw_priv_dereference(), addr, &uiRegValue);
	regmask = ~((1<<startBit) -1);
	regmask &= ((1<<endBit) -1)|(1<<endBit);
	uiRegValue &= ~regmask;
	uiRegValue |= (data <<startBit)&regmask;
	atbm_direct_write_reg_32(atbm_hw_priv_dereference(), addr, uiRegValue);	
}

unsigned char char2Hex(const char chart)
{
	unsigned char ret = 0;
	if((chart>='0')&&(chart<='9')){
		ret = chart-'0';		
	}else if((chart>='a')&&(chart<='f')){
		ret = chart - 'a'+0x0a;		
	}else if((chart>='A')&&(chart<='F')){
		ret = chart - 'A'+0x0a;
	}
	return ret;
}

/*
Func: str2mac
Param: 
	str->string format of MAC address
	i.e. 00:11:22:33:44:55
Return: 
	error -1
	OK 0
*/
int str2mac(char *dst_mac, char *src_str)
{
	int i;
	
	if(dst_mac == NULL || src_str == NULL)
		return -1;

	for(i=0; i<6; i++){
		dst_mac[i] = (char2Hex(src_str[i*3]) << 4) + (char2Hex(src_str[i*3 + 1]));
		atbm_printk_wext("str2mac: %x\n", dst_mac[i]);
	}

	return 0;	
}


int DCXOCodeWrite(struct atbm_common *hw_priv,u8 data)
{
#ifndef SPI_BUS
	u32 uiRegData;
	atbm_direct_read_reg_32(hw_priv, DCXO_TRIM_REG, &uiRegData);
	//hw_priv->sbus_ops->sbus_read_sync(hw_priv->sbus_priv,DCXO_TRIM_REG,&uiRegData,4);
	uiRegData &= ~0x40003F;

	uiRegData |= (((data&0x40)<<16)|(data&0x3f));
	
	atbm_direct_write_reg_32(hw_priv, DCXO_TRIM_REG, uiRegData);
	//hw_priv->sbus_ops->sbus_write_sync(hw_priv->sbus_priv,DCXO_TRIM_REG,&uiRegData,4);
#endif
	return 0;
}

u8 DCXOCodeRead(struct atbm_common *hw_priv)
{	
#ifndef SPI_BUS

	u32 uiRegData;
	u8 dcxo;
	u8 dcxo_hi,dcxo_low;

	atbm_direct_read_reg_32(hw_priv, DCXO_TRIM_REG, &uiRegData);
	//hw_priv->sbus_ops->sbus_read_sync(hw_priv->sbus_priv,DCXO_TRIM_REG,&uiRegData,4);//
	dcxo_hi = (uiRegData>>22)&0x01;
	dcxo_low = uiRegData&0x3f;
	dcxo = (dcxo_hi << 6) + (dcxo_low&0x3f);
	
	return dcxo;
#else
	return 0;
#endif
}

extern int atbm_direct_read_reg_32(struct atbm_common *hw_priv, u32 addr, u32 *val);
extern int atbm_direct_write_reg_32(struct atbm_common *hw_priv, u32 addr, u32 val);
extern struct etf_test_config etf_config;
//get chip crystal type
u32 GetChipCrystalType(struct atbm_common *hw_priv)
{	
#ifndef SPI_BUS
	u32 pin_reg;
	u32 pin_reg17400000;
	
	atbm_direct_read_reg_32(hw_priv, 0x17400000, &pin_reg17400000);
	atbm_direct_write_reg_32(hw_priv, 0x17400000, pin_reg17400000 | BIT(8));
	atbm_direct_read_reg_32(hw_priv, 0x17400000, &pin_reg17400000);
	if (pin_reg17400000 & BIT(17))
	{
		etf_config.chip_crystal_type = 1;
	}
	atbm_direct_read_reg_32(hw_priv, 0x16101010, &pin_reg);
	if (pin_reg & BIT(5))
	{
		etf_config.chip_crystal_type |= BIT(1);
	}
	if (pin_reg & BIT(27))
	{
		etf_config.chip_crystal_type |= BIT(2);
	}
	atbm_direct_write_reg_32(hw_priv, 0x17400000, pin_reg17400000);

	atbm_printk_always("crystal:%d\n",etf_config.chip_crystal_type);
	return pin_reg17400000;
#else
	return 0;
#endif
}

int ieee80211_set_channel(struct wiphy *wiphy,
				 struct net_device *netdev,
				 struct ieee80211_channel *chan,
				 enum nl80211_channel_type channel_type);

static void atbm_internal_cmd_scan_dump(struct ieee80211_internal_scan_request *scan_req)
{
	int i;
	if(scan_req->n_ssids){
		for(i = 0;i<scan_req->n_ssids;i++){
			atbm_printk_debug("%s: ssid[%s][%d]\n",__func__,scan_req->ssids[i].ssid,scan_req->ssids[i].ssid_len);
		}
	}	
	if(scan_req->n_channels){
		for(i = 0;i<scan_req->n_channels;i++){
			atbm_printk_debug("%s: channel[%d]\n",__func__,scan_req->channels[i]);
		}
	}
	if(scan_req->n_macs){
		for(i = 0;i<scan_req->n_macs;i++){
			atbm_printk_debug("%s: mac[%pM]\n",__func__,scan_req->macs[i].mac);
		}
	}
	atbm_printk_debug("%s: ie_len[%d]\n",__func__,scan_req->ie_len);
}

bool  atbm_internal_cmd_scan_build(struct ieee80211_local *local,struct ieee80211_internal_scan_request *req,
											   u8* channels,int n_channels,struct cfg80211_ssid *ssids,int n_ssids,
											   struct ieee80211_internal_mac *macs,int n_macs)
{
	u8* local_scan_ie;
	u8* scan_ie;
	int ie_len;
	/*
	*use default internal handle
	*/
	req->result_handle = NULL;
	req->priv = NULL;

	req->channels = channels;
	req->n_channels = n_channels;
	
	req->ssids =  ssids;
	req->n_ssids = n_ssids;

	req->macs = macs;
	req->n_macs = n_macs;

	req->no_cck = true;
	
	rcu_read_lock();
	local_scan_ie = rcu_dereference(local->internal_scan_ie);
	ie_len  = local->internal_scan_ie_len;

	if(local_scan_ie && ie_len){
		scan_ie = atbm_kzalloc(ie_len,GFP_ATOMIC);

		if(scan_ie == NULL){
			rcu_read_unlock();
			return false;
		}
		memcpy(scan_ie,local_scan_ie,ie_len);
		req->ies = scan_ie;
		req->ie_len = ie_len;
	}else {
		req->ies = NULL;
		req->ie_len = 0;
	}
	rcu_read_unlock();

	return true;
}
bool atbm_internal_cmd_scan_triger(struct ieee80211_sub_if_data *sdata,struct ieee80211_internal_scan_request *req)
{
	struct cfg80211_scan_request *scan_req = NULL;
	struct ieee80211_local *local  = sdata->local;
	u8 n_channels = 0;
	int i;
	struct wiphy *wiphy = local->hw.wiphy;
	u8 index;
	void *pos;
	void *pos_end;
	long status = 20*HZ;
	
	ASSERT_RTNL();
	ieee80211_scan_cancel(local);
	atbm_flush_workqueue(local->workqueue);
	
	mutex_lock(&local->mtx);

	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_scan("%s:%d\n",__func__,__LINE__);
		goto err;
	}
	
	if (local->scan_req)
	{
		atbm_printk_scan("%s:%d\n",__func__,__LINE__);
		goto err;
	}
#ifdef CONFIG_ATBM_SUPPORT_P2P
	if (!list_empty(&local->roc_list))
	{
		goto err;
	}
#endif
	if (ieee80211_work_busy(local)) {
		
		atbm_printk_scan("%s(%s):work_list is not empty,pend scan\n",__func__,sdata->name);
		goto err;
	}
	
	if(atbm_ieee80211_suspend(sdata->local)==true){
		
		atbm_printk_err("ieee80211_scan drop:suspend\n");
		goto err;
	}
	
	if(req->n_channels == 0){
		for (i = 0; i < IEEE80211_NUM_BANDS; i++)
			if (wiphy->bands[i])
				n_channels += wiphy->bands[i]->n_channels;
	}else {
		n_channels = req->n_channels;
	}
	scan_req = atbm_kzalloc(sizeof(*scan_req)
			+ sizeof(*scan_req->ssids) * req->n_ssids
			+ sizeof(*scan_req->channels) * n_channels
			+ req->ie_len + req->n_channels + sizeof(struct ieee80211_internal_mac)*req->n_macs, GFP_KERNEL);
	
	if(scan_req == NULL){
		atbm_printk_scan("%s:atbm_kzalloc scan_req err\n",__func__);
		goto err;
	}
	pos = (void *)&scan_req->channels[n_channels];
	pos_end = (void*)((u8*)pos+sizeof(*scan_req->ssids) * req->n_ssids+
			  req->ie_len + req->n_channels + sizeof(struct ieee80211_internal_mac)*req->n_macs);
	/*
	*set channel
	*/
	if(req->n_channels){
		int freq;
		for (i = 0;i<req->n_channels;i++){
			
			if(req->channels[i] <= 14){
				freq = 2412+(req->channels[i] - 1)*5;
				if(req->channels[i] == 14)
						freq = 2484;
			}else {
				freq = 5000 + (5*req->channels[i]);
			}

			atbm_printk_debug("%s:channel(%d),freq(%d)\n",__func__,req->channels[i],freq);

			scan_req->channels[i] = ieee80211_get_channel(wiphy,freq);

			if(scan_req->channels[i] == NULL){
				goto err;
			}
		}
	}else {
		enum ieee80211_band band;
		i = 0;
		/* all channels */
		for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
			int j;
			if (!wiphy->bands[band])
				continue;
			for (j = 0; j < wiphy->bands[band]->n_channels; j++) {
				scan_req->channels[i] =  &wiphy->bands[band]->channels[j];
				i++;
			}
		}
	}
	scan_req->n_channels = n_channels;
	/*
	*set ssid
	*/
	if( req->n_ssids){
		scan_req->ssids = (void *)pos;
		for(i=0;i<req->n_ssids;i++){			
			atbm_printk_debug("%s:scan ssid(%s)(%d)\n",__func__,req->ssids[i].ssid,req->ssids[i].ssid_len);
			scan_req->ssids[i].ssid_len = req->ssids[i].ssid_len;
			memcpy(scan_req->ssids[i].ssid,req->ssids[i].ssid,req->ssids[i].ssid_len);
		}
		pos = scan_req->ssids+req->n_ssids;
	}
	scan_req->n_ssids = req->n_ssids;
	/*
	*set macs
	*/
	local->internal_scan.req.n_macs = req->n_macs;	
	if(req->n_macs){
		local->internal_scan.req.macs = pos;
		memcpy(local->internal_scan.req.macs, req->macs,sizeof(struct ieee80211_internal_mac)*req->n_macs);
		pos = local->internal_scan.req.macs + req->n_macs;
	}
	/*
	*set ie
	*/
	if (req->ie_len) {		
		scan_req->ie = (void *)pos;
		memcpy((void*)scan_req->ie,req->ies,req->ie_len);
		scan_req->ie_len = req->ie_len;
		pos = (u8*)scan_req->ie+req->ie_len;
	}

	/*
	*set channel
	*/
	if(req->channels){
		local->internal_scan.req.channels = pos;
		memcpy(local->internal_scan.req.channels,req->channels,req->n_channels);
	    pos = local->internal_scan.req.channels+req->n_channels;
	}
	WARN_ON(pos != pos_end);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0))
	for (i = 0; i < IEEE80211_NUM_BANDS; i++)
		if (wiphy->bands[i])
			scan_req->rates[i] =
				(1 << wiphy->bands[i]->n_bitrates) - 1;
		
	scan_req->no_cck = req->no_cck;
#endif
	
	scan_req->wiphy = wiphy;

	local->internal_scan.req.n_channels = req->n_channels;	
	local->internal_scan.req.ies = (u8*)scan_req->ie;
	local->internal_scan.req.ie_len = scan_req->ie_len;
	local->internal_scan.req.ssids = scan_req->ssids;
	local->internal_scan.req.n_ssids = scan_req->n_ssids;
	memcpy(local->internal_scan.req.bssid,req->bssid,6);

	local->internal_scan.req.req_flags = req->req_flags;
	local->internal_scan.req.etf = req->etf;
	
	rcu_assign_pointer(local->internal_scan.req.result_handle,req->result_handle);
	rcu_assign_pointer(local->internal_scan.req.priv,req->priv);

	atbm_common_hash_list_init(local->internal_scan.mac_hash_list,IEEE80211_INTERNAL_SCAN_HASHENTRIES);
	
	for(index = 0;index<local->internal_scan.req.n_macs;index++){
		int hash_index = atbm_hash_index(local->internal_scan.req.macs[index].mac,6,IEEE80211_INTERNAL_SCAN_HASHBITS);
		struct hlist_head *hlist = &local->internal_scan.mac_hash_list[hash_index];
		hlist_add_head(&local->internal_scan.req.macs[index].hnode,hlist);
	}
	
	atbm_internal_cmd_scan_dump(&local->internal_scan.req);
	
	if(ieee80211_internal_scan_triger(sdata,scan_req) == false){
		atbm_printk_scan("%s scan triger err\n",__func__);
		
		for(index = 0;index<local->internal_scan.req.n_macs;index++){
			hlist_del(&local->internal_scan.req.macs[index].hnode);
		}
		rcu_assign_pointer(local->internal_scan.req.result_handle,NULL);
		rcu_assign_pointer(local->internal_scan.req.priv,NULL);
		memset(&local->internal_scan.req,0,sizeof(struct ieee80211_internal_scan_sta));
		goto err;
	}	
	if(local->scan_req_wrap.flags & IEEE80211_SCAN_REQ_SPILT){
		status = 60*HZ;
	}
	mutex_unlock(&local->mtx);

	status = wait_event_timeout(local->internal_scan_wq,atomic_read(&local->internal_scan_status) != IEEE80211_INTERNAL_SCAN_STATUS__WAIT,status);

	if(status == 0){
		return false;
	}

	atbm_printk_debug("%s: status(%ld)\n",__func__,status);

	if(atomic_read(&local->internal_scan_status) == IEEE80211_INTERNAL_SCAN_STATUS__ABORT)
		return false;
	
	return true;
err:
	if(scan_req)
		atbm_kfree(scan_req);
	mutex_unlock(&local->mtx);

	return false;
}

bool atbm_internal_cmd_stainfo(struct ieee80211_local *local,struct ieee80211_internal_sta_req *sta_req)
{
	struct ieee80211_internal_sta_info stainfo;
	struct sta_info *sta;
	u8 index = 0;
	struct hlist_head *hhead;
	struct hlist_node *node;
	struct ieee80211_internal_mac *mac_node;
	unsigned int hash_index = 0;
	bool (__rcu *sta_handle)(struct ieee80211_internal_sta_info *stainfo,void *priv);	
	struct hlist_head atbm_sta_mac_hlist[ATBM_COMMON_HASHENTRIES];

	
	memset(&stainfo,0,sizeof(struct ieee80211_internal_sta_info));	
	
	WARN_ON(sta_req->sta_handle == NULL);
	BUG_ON((sta_req->n_macs != 0)&&(sta_req->macs == NULL));
	
	atbm_common_hash_list_init(atbm_sta_mac_hlist,ATBM_COMMON_HASHENTRIES);

	for(index = 0;index<sta_req->n_macs;index++){
		hash_index = atbm_hash_index(sta_req->macs[index].mac,
								 6,ATBM_COMMON_HASHBITS);

		hhead = &atbm_sta_mac_hlist[hash_index];
		hlist_add_head(&sta_req->macs[index].hnode,&atbm_sta_mac_hlist[hash_index]);
	}
	
	mutex_lock(&local->sta_mtx);
	sta_handle = rcu_dereference(sta_req->sta_handle);
	list_for_each_entry_rcu(sta, &local->sta_list, list) {
		struct ieee80211_channel_state *chan_state = ieee80211_get_channel_state(local, sta->sdata);

		if(sta->sdata->vif.type != sta_req->type){
			continue;
		}
		
		if(sta->uploaded == false){
			continue;
		}
		
		if(sta->dead == true){
			continue;
		}
		
		if(sta_req->n_macs){
			u8 sta_needed = false;
			
			hash_index = atbm_hash_index(sta->sta.addr,6,ATBM_COMMON_HASHBITS);
			hhead = &atbm_sta_mac_hlist[hash_index];
			hlist_for_each(node,hhead){
				mac_node = hlist_entry(node,struct ieee80211_internal_mac,hnode);
				if (memcmp(mac_node->mac,sta->sta.addr,6) == 0){
					sta_needed = true;
					break;
				}
			}
			
			if(sta_needed == false){
				continue;
			}
		}
		stainfo.sdata = sta->sdata;
		
		if(sta_req->req_flag&IEEE80211_INTERNAL_STA_FLAGS_CHANNEL){
			stainfo.channel = channel_hw_value(chan_state->oper_channel);
			stainfo.channel_type = !!(test_sta_flag(sta,WLAN_STA_40M_CH)&&!test_sta_flag(sta,WLAN_STA_40M_CH_SEND_20M));
		}
		
		if(sta_req->req_flag&IEEE80211_INTERNAL_STA_FLAGS_SIGNAL){
			stainfo.signal = sta->last_signal2;
			stainfo.avg_signal = (s8) -atbm_ewma_read(&sta->avg_signal2);
		}
		
		if(sta_req->req_flag&IEEE80211_INTERNAL_STA_FLAGS_TXRXBYTE){
			stainfo.rx_bytes = sta->rx_bytes;
			stainfo.tx_bytes = sta->tx_bytes;
		}

		if(sta_req->req_flag&IEEE80211_INTERNAL_STA_FLAGS_TOPRATE){			
			struct atbm_common *hw_priv = (struct atbm_common *)local->hw.priv;
			struct atbm_vif *priv = (struct atbm_vif *)sta->sdata->vif.drv_priv;
			if(sta->sdata->vif.type == NL80211_IFTYPE_STATION){				
				wsm_read_mib(hw_priv, WSM_MIB_ID_GET_RATE, &stainfo.top_rate, sizeof(unsigned int), priv->if_id);
			}else if(sta->sdata->vif.type == NL80211_IFTYPE_AP){
				struct atbm_sta_priv *sta_priv = (struct atbm_sta_priv *)&sta->sta.drv_priv;
				u8 sta_id = (u8)sta_priv->link_id;
				if(sta_id != 0){					
					wsm_write_mib(hw_priv, WSM_MIB_ID_GET_RATE, &sta_id, 1,priv->if_id);
					wsm_read_mib(hw_priv, WSM_MIB_ID_GET_RATE, &stainfo.top_rate, sizeof(unsigned int), priv->if_id);
				}
			}
			stainfo.top_rate = stainfo.top_rate/2;
		}

		if(sta_req->req_flag&IEEE80211_INTERNAL_STA_FLAGS_SSID){
			rcu_read_lock();
			
			stainfo.ssid_len = 0;
			memset(stainfo.ssid,0,IEEE80211_MAX_SSID_LEN);
			
			if(sta->sdata->vif.type == NL80211_IFTYPE_STATION){
				struct cfg80211_bss *cbss = sta->sdata->u.mgd.associated;
				
				if(cbss){
					const char *ssid = NULL;
                    ssid = ieee80211_bss_get_ie(cbss, ATBM_WLAN_EID_SSID);
                    if(ssid){						
                        memcpy(stainfo.ssid, &ssid[2], ssid[1]);
                        stainfo.ssid_len = ssid[1];
                    }
				}				
			}else if(sta->sdata->vif.type == NL80211_IFTYPE_AP){
				struct ieee80211_bss_conf *bss_conf = &sta->sdata->vif.bss_conf;
				stainfo.ssid_len = bss_conf->ssid_len;
				if(stainfo.ssid_len)
					memcpy(stainfo.ssid,bss_conf->ssid,stainfo.ssid_len);
				
			}else {
				WARN_ON(1);
			}
			rcu_read_unlock();
		}
		memcpy(stainfo.mac,sta->sta.addr,6);
		stainfo.filled = sta_req->req_flag;
		if(sta_handle)
			sta_handle(&stainfo,sta_req->priv);
		
		memset(&stainfo,0,sizeof(struct ieee80211_internal_sta_info));
	}
	mutex_unlock(&local->sta_mtx);

	return true;
}
bool atbm_internal_cmd_monitor_req(struct ieee80211_sub_if_data *sdata,struct ieee80211_internal_monitor_req *monitor_req)
{
	struct ieee80211_local *local  = sdata->local;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;
	bool res = false;
	unsigned int freq;
	struct ieee80211_sub_if_data *other_sdata;
	
	struct ieee80211_channel *chan;
	enum nl80211_iftype old_type = sdata->vif.type;
	
	if(!ieee80211_sdata_running(sdata)){
		return false;
	}
	
	if(priv->join_status != ATBM_APOLLO_JOIN_STATUS_PASSIVE){
		return false;
	}

	list_for_each_entry(other_sdata, &local->interfaces, list){

		if(!ieee80211_sdata_running(other_sdata)){
			continue;
		}

		priv = (struct atbm_vif *)other_sdata->vif.drv_priv;

		if(priv->join_status != ATBM_APOLLO_JOIN_STATUS_PASSIVE){
			return false;
		}
	}
	if(ieee8011_channel_valid(&local->hw,monitor_req->ch) == false){
		return false;
	}
	
	switch(monitor_req->chtype){
	case NL80211_CHAN_NO_HT:
	case NL80211_CHAN_HT20:
	case NL80211_CHAN_HT40MINUS:
	case NL80211_CHAN_HT40PLUS:
		break;
	default:
		atbm_printk_err("error, %d\n", monitor_req->chtype);
		return false;
	}

	if(monitor_req->ch <= 14){
		freq = 2412+(monitor_req->ch - 1)*5;
	}else {
		freq = 5000 + (5*monitor_req->ch);
	}
	chan = ieee80211_get_channel(local->hw.wiphy, freq);

	if(chan == NULL){
		return false;
	}
	
	local->internal_monitor.req.ch = monitor_req->ch;
	local->internal_monitor.req.chtype = monitor_req->chtype;
	
	rcu_assign_pointer(local->internal_monitor.req.monitor_rx,monitor_req->monitor_rx);
	rcu_assign_pointer(local->internal_monitor.req.priv,monitor_req->priv);
	
	atbm_printk_debug("%s:[%s] channel %d\n",__func__,sdata->name,local->internal_monitor.req.ch);
	if(ieee80211_if_change_type(sdata, NL80211_IFTYPE_MONITOR)){
		res  = false;
		goto err;
	}

	if(ieee80211_set_channel(local->hw.wiphy,sdata->dev,chan,monitor_req->chtype)){
		goto err;
	}

	return true;
err:
	ieee80211_if_change_type(sdata,old_type);
	rcu_assign_pointer(local->internal_monitor.req.monitor_rx,NULL);
	rcu_assign_pointer(local->internal_monitor.req.priv,NULL);
	local->internal_monitor.req.ch = 0;
	
	return res;
}

bool atbm_internal_cmd_stop_monitor(struct ieee80211_sub_if_data *sdata)
{
	if(!ieee80211_sdata_running(sdata)){
		return false;
	}

	if(sdata->vif.type != NL80211_IFTYPE_MONITOR){
		return false;
	}

	ieee80211_if_change_type(sdata,NL80211_IFTYPE_STATION);

	rcu_assign_pointer(sdata->local->internal_monitor.req.monitor_rx,NULL);
	rcu_assign_pointer(sdata->local->internal_monitor.req.priv,NULL);

	synchronize_rcu();
	sdata->local->internal_monitor.req.ch = 0;
	sdata->local->internal_monitor.req.chtype = 0;
	
	return true;
}
bool atbm_internal_cmd_req_iftype(struct ieee80211_sub_if_data *sdata,struct ieee80211_internal_iftype_req *req)
{
	enum nl80211_iftype new_iftype;
	enum nl80211_iftype old_iftype = sdata->vif.type;
	struct ieee80211_local *local = sdata->local;
	bool change_channel = true;
	bool change_iftype  = true;
	
	ASSERT_RTNL();
	atbm_printk_debug("%s:type(%d),channel(%d)\n",__func__,req->if_type,req->channel);
	
	if (sdata->vif.type == NL80211_IFTYPE_STATION && sdata->u.mgd.associated){
		
		goto params_err;
	}
	
	if (sdata->vif.type == NL80211_IFTYPE_AP && sdata->u.ap.beacon){
		
		goto params_err;
	}
	
	switch(req->if_type){
	case IEEE80211_INTERNAL_IFTYPE_REQ__MANAGED:
		new_iftype = NL80211_IFTYPE_STATION;
		if(new_iftype == sdata->vif.type){
			change_iftype  = false;
		}
		change_channel = false;
		break;
	case IEEE80211_INTERNAL_IFTYPE_REQ__MONITOR:
		new_iftype = NL80211_IFTYPE_MONITOR;		
		if(new_iftype == sdata->vif.type){
			change_iftype = false;
		}
		break;
	default:
		goto params_err;
	}

	if(change_iftype == true){
		if(ieee80211_if_change_type(sdata, new_iftype)){
			goto params_err;
		}
	}
	if(change_channel == true) {
		struct ieee80211_channel *chan = ieee8011_chnum_to_channel(&sdata->local->hw,req->channel);

		if(chan == NULL){
			goto interface_err;
		}

		if(ieee80211_set_channel(local->hw.wiphy,sdata->dev,chan,NL80211_CHAN_HT20)){
			goto interface_err;
		}
	}

	return true;
interface_err:
	ieee80211_if_change_type(sdata,old_iftype);
params_err:
	return false;
}
bool atbm_internal_wsm_adaptive(struct atbm_common *hw_priv,struct ieee80211_internal_wsm_adaptive *adaptive)
{
	char* cmd = NULL;
	int len;
	bool res = true;
	
	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		res = false;
		goto err;
	}
	
	len = snprintf(cmd,ATBM_WSM_CMD_LEN,ATBM_WSM_ADAPTIVE"%d",adaptive->enable);

	if(len<=0){
		res = false;
		goto err;
	}
	if(len+1>ATBM_WSM_CMD_LEN){
		res = false;
		goto err;
	}
	atbm_printk_debug("%s:wsm [%s][%d]\n",__func__,cmd,len);
	
	if( wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1,0) < 0){
		res = false;
	}
	
err:
	if(cmd)
		atbm_kfree(cmd);
	return res;
}

bool atbm_internal_wsm_txpwr_dcxo(struct atbm_common *hw_priv,struct ieee80211_internal_wsm_txpwr_dcxo *txpwr_dcxo)
{
	int len;
	char* cmd = NULL;
	bool res = true;
	
	if(txpwr_dcxo->txpwr_L > 32 || txpwr_dcxo->txpwr_L < -32){
		atbm_printk_err("error, txpwr_L %d\n", txpwr_dcxo->txpwr_L);
		res = false;
		goto err;
	}
	
	if(txpwr_dcxo->txpwr_M > 32 || txpwr_dcxo->txpwr_M < -32){
		atbm_printk_err("error, txpwr_M %d\n", txpwr_dcxo->txpwr_M);
		res = false;
		goto err;
	}
	
	if(txpwr_dcxo->txpwr_H > 32 || txpwr_dcxo->txpwr_H < -32){
		atbm_printk_err("error, txpwr_H %d\n", txpwr_dcxo->txpwr_H);
		res = false;
		goto err;
	}
	
	if(txpwr_dcxo->dcxo > 127 || txpwr_dcxo->dcxo < 0){
		atbm_printk_err("error, dcxo %d\n", txpwr_dcxo->dcxo);
		res = false;
		goto err;
	}

	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		res = false;
		goto err;
	}

	len = snprintf(cmd, ATBM_WSM_CMD_LEN,"set_txpwr_and_dcxo,%d,%d,%d,%d ",
		           txpwr_dcxo->txpwr_L,txpwr_dcxo->txpwr_M, txpwr_dcxo->txpwr_H, txpwr_dcxo->dcxo);

	if(len<=0){
		res = false;
		goto err;
	}
	if(len+1>ATBM_WSM_CMD_LEN){
		res = false;
		goto err;
	}
	atbm_printk_debug("%s:wsm [%s][%d]\n",__func__,cmd,len);
	if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
		res = false;
	}
err:
	if(cmd)
		atbm_kfree(cmd);
	return res;
}

bool atbm_internal_wsm_txpwr(struct atbm_common *hw_priv,struct ieee80211_internal_wsm_txpwr *txpwr)
{
	int len;
	char* cmd = NULL;
	bool res = true;
	/*
	*0,3,15,63
	*/
	if(txpwr->txpwr_indx != 0 && 
	   txpwr->txpwr_indx != 3 &&
	   txpwr->txpwr_indx != 15 &&
	   txpwr->txpwr_indx != 63){
		atbm_printk_err("error, txpwr_indx %d\n", txpwr->txpwr_indx);
		res = false;
		goto err;
	}

	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		res = false;
		goto err;
	}

	len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_TXPWR"%d",txpwr->txpwr_indx);

	if(len<=0){
		res = false;
		goto err;
	}

	if(len+1>ATBM_WSM_CMD_LEN){
		res = false;
		goto err;
	}
	atbm_printk_debug("%s:wsm [%s][%d]\n",__func__,cmd,len);
	if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
		res = false;
	}
err:
	if(cmd)
		atbm_kfree(cmd);
	return res;
}
bool atbm_internal_wsm_set_rate(struct atbm_common *hw_priv,struct ieee80211_internal_rate_req *req)
{
	int len;
	char* cmd = NULL;
	bool res = true;

	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		res = false;
		goto err;
	}

	if(req->flags & IEEE80211_INTERNAL_RATE_FLAGS_CLEAR_TX_RATE){
		len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_FIX_RATE,0);

		if(len<=0){
			res = false;
			goto err;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			res = false;
			goto err;
		}

		memset(cmd,0,ATBM_WSM_CMD_LEN);
	}

	if(req->flags & IEEE80211_INTERNAL_RATE_FLAGS_CLEAE_TOP_RATE){
		len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_TOP_RATE,0);

		if(len<=0){
			res = false;
			goto err;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			res = false;
			goto err;
		}

		memset(cmd,0,ATBM_WSM_CMD_LEN);
	}

	if(req->flags & IEEE80211_INTERNAL_RATE_FLAGS_CLEAR_MIN_RATE){
		len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_MIN_RATE,0);

		if(len<=0){
			res = false;
			goto err;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			res = false;
			goto err;
		}

		memset(cmd,0,ATBM_WSM_CMD_LEN);
	}
	
	if(req->flags & IEEE80211_INTERNAL_RATE_FLAGS_SET_TX_RATE){
		len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_FIX_RATE,req->rate);

		if(len<=0){
			res = false;
			goto err;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			res = false;
			goto err;
		}

		memset(cmd,0,ATBM_WSM_CMD_LEN);
	}

	if(req->flags & IEEE80211_INTERNAL_RATE_FLAGS_SET_TOP_RATE){
		len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_TOP_RATE,req->rate);

		if(len<=0){
			res = false;
			goto err;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			res = false;
			goto err;
		}

		memset(cmd,0,ATBM_WSM_CMD_LEN);
	}

	if(req->flags & IEEE80211_INTERNAL_RATE_FLAGS_SET_MIN_RATE){
		len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_MIN_RATE,req->rate);

		if(len<=0){
			res = false;
			goto err;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			res = false;
			goto err;
		}

		memset(cmd,0,ATBM_WSM_CMD_LEN);
	}
err:
	if(cmd)
		atbm_kfree(cmd);
	return res;
}

bool atbm_internal_wsm_set_rate_power(struct atbm_common *hw_priv,
												   struct ieee80211_internal_rate_power_req *req)
{
	#define MIN_RATE_INDEX	(0)
	#define MAX_RATE_INDEX	(10)
	#define MIN_POWER		(-16)
	#define MAX_POWER		(16)

	bool ret = true;
	char* cmd = NULL;
	int len = 0;
	
	if((req->rate_index < MIN_RATE_INDEX) ||(req->rate_index > MAX_RATE_INDEX)){
		ret = false;
		goto exit;
	}

	if((req->power < MIN_POWER) ||(req->power > MAX_POWER)){
		ret = false;
		goto exit;
	}
	
	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		ret = false;
		goto exit;
	}

	len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_SET_RATE_POWER,req->rate_index,req->power);

	if(len <= 0){
		ret = false;
		goto exit;
	}

	if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
		ret = false;
		goto exit;
	}
	
exit:
	if(cmd)
		atbm_kfree(cmd);

	return ret;

	#undef MIN_RATE_INDEX
	#undef MAX_RATE_INDEX
	#undef MIN_POWER
	#undef MAX_POWER
}
static char spec_oui_buf[256];
static char *spec_oui = "NULL";
module_param(spec_oui,charp,0644);
MODULE_PARM_DESC(spec_oui,"special oui");
void atbm_set_special_oui(struct atbm_common *hw_priv, char *pdata, int len)
{
    memset(spec_oui_buf, 0, 256);
    memcpy(spec_oui_buf, pdata, len);
    spec_oui = spec_oui_buf;
}
static int wifi_tx_pw = 0;
static char wifi_txpw_buf[64]={0};
static char *wifi_txpw = "NULL";
module_param(wifi_txpw,charp,0644);
MODULE_PARM_DESC(wifi_txpw,"wifi tx power");

int atbm_get_tx_power(void)
{
	return wifi_tx_pw;
}

void atbm_set_tx_power(struct atbm_common *hw_priv, int txpw)
{
	char *p20, *p40, *pHT;
	
	wifi_tx_pw = txpw;

	if(wifi_tx_pw & BIT(0))
		p20 = "20M-High ";
	else
		p20 = "20M-Normal ";


	if(wifi_tx_pw & BIT(1))
		p40 = "40M-High ";
	else
		p40 = "40M-Normal ";

	if((hw_priv->channel_type == NL80211_CHAN_HT20)||(hw_priv->channel_type == NL80211_CHAN_NO_HT))
		pHT = "20M-Mode";
	else
		pHT = "40M-Mode";

	memset(wifi_txpw_buf, 0, sizeof(wifi_txpw_buf));
	sprintf(wifi_txpw_buf, "%s, %s, %s", p20, p40, pHT);
	wifi_txpw = wifi_txpw_buf;

	return;
}												   
#define ATBM_SPECIAL_FREQ_MAX_LEN		128
static char wifi_freq_buf[ATBM_SPECIAL_FREQ_MAX_LEN]={0};
static char *wifi_freq = "NULL";
module_param(wifi_freq,charp,0644);
MODULE_PARM_DESC(wifi_freq,"wifi freq");
void atbm_set_freq(struct ieee80211_local *local)
{

   struct hlist_head *hlist;
   struct hlist_node *node;
   struct hlist_node *node_temp;
   struct ieee80211_special_freq *freq_node;
   int hash_index = 0;
   int n_freqs = 0;
   int len = 0;
   int total_len = 0;
   char *freq_show = wifi_freq_buf;
   
   memset(freq_show,0,ATBM_SPECIAL_FREQ_MAX_LEN);
   
   for(hash_index = 0;hash_index<ATBM_COMMON_HASHENTRIES;hash_index++){
	   hlist = &local->special_freq_list[hash_index];
	   hlist_for_each_safe(node,node_temp,hlist){
		   freq_node = hlist_entry(node,struct ieee80211_special_freq,hnode);
		   n_freqs ++ ;
		   len = scnprintf(freq_show+total_len,ATBM_SPECIAL_FREQ_MAX_LEN-total_len,"ch:%d, freq:%d \n",
			   channel_hw_value(freq_node->channel),freq_node->freq);
		   total_len += len;
	   }
   }

   if(n_freqs == 0){
	   wifi_freq = "NULL";
   }else {
	   wifi_freq = wifi_freq_buf;
   }
   
#if 0
   int i;
   
   memset(wifi_freq_buf, 0, sizeof(wifi_freq_buf));
   for(i=0; i<CHANNEL_NUM; i++){
	   if(pdata[i].flag == 1){
		   sprintf(wifi_freq_buf+strlen(wifi_freq_buf), "ch:%d, freq:%d \n", i+1, pdata[i].special_freq);
	   }
   }
   
   wifi_freq = wifi_freq_buf;

   return;
#endif
}
bool atbm_internal_freq_set(struct ieee80211_hw *hw,struct ieee80211_internal_set_freq_req *req)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct atbm_common *hw_priv = (struct atbm_common *)hw->priv;
	struct ieee80211_channel *channel;
	char* cmd = NULL;
	int len;
	bool res = true;
	struct ieee80211_special_freq special_req;
	
	ASSERT_RTNL();

	channel = ieee8011_chnum_to_channel(hw,req->channel_num);

	if(channel == NULL){
		res = false;
		goto out;
	}
	
	if(req->set == false){
		req->freq = channel_center_freq(channel);
	}
	
	if((req->freq < 2300) || (req->freq>2600)){
		res = false;
		goto out;
	}
	
	mutex_lock(&local->mtx);
	__ieee80211_recalc_idle(local);
	mutex_unlock(&local->mtx);

	if((local->hw.conf.flags & IEEE80211_CONF_IDLE) == 0){
		res = false;
		goto out;
	}

	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		res = false;
		goto out;
	}

	len = snprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_SET_FREQ,req->channel_num,(int)req->freq);

	if(len <= 0){
		res = false;
		goto out;
	}

	if(len+1>ATBM_WSM_CMD_LEN){
		res = false;
		goto out;
	}
	special_req.channel = channel;
	special_req.freq    = req->freq;
	
	if(channel_center_freq(channel) != req->freq){		
		if(ieee80211_special_freq_update(local,&special_req) == false){
			res = false;
			goto out;
		}
	}else {
		ieee80211_special_freq_clear(local,&special_req);
	}
	if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
		ieee80211_special_freq_clear(local,&special_req);
		res = false;
		goto out;
	}
out:
	if(cmd)
		atbm_kfree(cmd);

	return res;
}
bool atbm_internal_channel_auto_select(struct ieee80211_sub_if_data *sdata,
													  struct ieee80211_internal_channel_auto_select_req *req)
{
	struct ieee80211_internal_scan_request scan_req;
	
	scan_req.req_flags = IEEE80211_INTERNAL_SCAN_FLAGS__CCA;
	/*
	*all off supported channel will be scanned
	*/
	scan_req.channels   = NULL;
	scan_req.n_channels = 0;
	scan_req.macs       = NULL;
	scan_req.n_macs     = 0;
	scan_req.ies		= NULL;
	scan_req.ie_len		= 0;
	scan_req.no_cck     = false;
	scan_req.priv		= NULL;
	scan_req.result_handle = NULL;
	scan_req.ssids      = NULL;
	scan_req.n_ssids    = 0;

	return atbm_internal_cmd_scan_triger(sdata,&scan_req);
}

static bool atbm_internal_channel_auto_select_results_handle(struct ieee80211_hw *hw,struct atbm_internal_scan_results_req *req,struct ieee80211_internal_scan_sta *sta_info)
{
	struct ieee80211_internal_channel_auto_select_results *cca_results = (struct ieee80211_internal_channel_auto_select_results *)req->priv;
	s8 signal = (s8)sta_info->signal;
	u8 cur_channel = sta_info->channel;
	u8 index = 0;
	struct ieee80211_channel *channel;
	
	if(ieee8011_channel_valid(hw,cur_channel) == false){
		return false;
	}

	if(sta_info->cca == false){
		return false;
	}
	
	req->n_stas ++;
	cca_results->n_aps[cur_channel-1]++;
	
	if(cca_results->version == 1)
		cca_results->weight[cur_channel-1] += ieee80211_rssi_weight(signal);
	else 
		cca_results->weight[cur_channel-1]++;
	
	channel = ieee8011_chnum_to_channel(hw,cur_channel);

	if(channel_in_special(channel) == true){
		return true;
	}
	/*
	*2.4G channel
	*/
	atbm_printk_debug("ssid[%s],channel[%d],signal(%d)\n",sta_info->ssid,cur_channel,signal);
	/*
	*channel 1-13
	*weight[x] +=  val[x] + val[x-1] + val[x-2] + val[x-3] + val[x+1] + val[x+2] + val[x+3]
	*/
	if(cur_channel<=13){
		u8 low;
		u8 high;

		low = cur_channel>=4?cur_channel-3:1;
		high = cur_channel<= 10 ? cur_channel+3:13;
		
		for(index=cur_channel+1;index<=high;index++){
			channel = ieee8011_chnum_to_channel(hw,index);
			/*
			*skip special freq
			*/
			if(channel_in_special(channel) == true){
				atbm_printk_debug("%s:skip special freq(%d)\n",__func__,channel_hw_value(channel));
				continue;
			}
			
			if(cca_results->version == 1)
				cca_results->weight[index-1] += ieee80211_rssi_weight(signal - 2*(index-cur_channel));
			else 
				cca_results->weight[index-1] ++;
		}

		for(index=cur_channel-1;index>=low;index--){
			channel = ieee8011_chnum_to_channel(hw,index);
			/*
			*skip special freq
			*/
			if(channel_in_special(channel) == true){
				atbm_printk_debug("%s:skip special freq(%d)\n",__func__,channel_hw_value(channel));
				continue;
			}
			if(cca_results->version == 1)
				cca_results->weight[index-1] += ieee80211_rssi_weight(signal - 2*(cur_channel-index));
			else 
				cca_results->weight[index-1] ++;
		}
	}
	/*
	*channel 14
	*/
	else if(cur_channel == 14){
		
	}
	/*
	*5G channel
	*/
	else {
		
	}

	for(index = 0;index<IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX;index++){
		atbm_printk_debug("weight[%d]=[%d]\n",index,cca_results->weight[index]);
	}
	return true;
}
bool atbm_internal_channel_auto_select_results(struct ieee80211_sub_if_data *sdata,
												struct ieee80211_internal_channel_auto_select_results *results)
{
	#define ATBM_BUSY_RATIO_MIN		100
	struct atbm_internal_scan_results_req results_req;
	struct ieee80211_local *local = sdata->local;
	u8 *busy_ratio;
	u8 i;
	u32 min_ap_num = (u32)(-1);
	u8  min_busy_ratio = 128;
	u8  min_ap_num_ration = 128;
	u8 channel = 0;
	int band;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	u32 ignore_flags = IEEE80211_CHAN_DISABLED;
#endif
	struct ieee80211_supported_band *sband;
	u8 ignor_channel_mask[IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX];
	u8 channel_mask[IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX];

	results_req.n_stas = 0;
	results_req.flush = true;
	results_req.priv = results;
	results_req.result_handle = atbm_internal_channel_auto_select_results_handle;
	busy_ratio = ieee80211_scan_cca_val_get(&local->hw);
	
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	ignore_flags |= IEEE80211_CHAN_NO_OFDM;
#endif
	if(ieee80211_scan_internal_req_results(local,&results_req) == false){
		goto err;
	}
	
	for(i = 0;i<14;i++){
		atbm_printk_debug("busy_ratio[%d]=[%d]\n",i,busy_ratio[i]);
	}
	
	memset(ignor_channel_mask,0,IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX);
	memset(channel_mask,1,IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX);

	for(i= 0;i<results->ignore_n_channels;i++){
		
		BUG_ON(results->ignore_channels == NULL);
		
		if(ieee8011_channel_valid(&local->hw,results->ignore_channels[i]) == false){
			goto err;
		}
		ignor_channel_mask[results->ignore_channels[i]-1] = 1;
		
		atbm_printk_debug("%s channel %d ignored\n",__func__,results->ignore_channels[i]);
	}

	if(results->n_channels){
		memset(channel_mask,0,IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX);
		for(i = 0;i<results->n_channels;i++){
			BUG_ON(results->channels == NULL);
			if(ieee8011_channel_valid(&local->hw,results->channels[i]) == false){
				goto err;
			}

			channel_mask[results->channels[i]-1] = 1;
		}
	}
	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		
		sband = local->hw.wiphy->bands[band];
		
		if (!sband)
			continue;
		/*
		*2.4G channel and 5G
		*/
		for(i = 0;i<sband->n_channels;i++){
			/*
			*0 means that the channel do not process cca
			*/
			if(busy_ratio[channel_hw_value(&sband->channels[i])-1] == 0){
				continue;
			}
			
			if(ignor_channel_mask[channel_hw_value(&sband->channels[i])-1] == 1){
				continue;
			}

			if(channel_mask[channel_hw_value(&sband->channels[i])-1] == 0){
				continue;
			}
			/*
			*special freq must be skiped
			*/
			if(channel_in_special(&sband->channels[i])){
				atbm_printk_debug("%s:skip special freq(%d)\n",__func__,channel_hw_value(&sband->channels[i]));
				continue;
			}
			/*
			*some disabled channel must be skiped
			*/
			/**
			if(ignore_flags&sband->channels[i].flags){
				atbm_printk_debug("%s: channel[%d] not support ofdm\n",__func__,channel_hw_value(&sband->channels[i]));
				continue;
			}
			*/
		//	atbm_printk_err("\n");
	//		atbm_printk_err("channel[%d] min_ap_num [%d]  min_ap_num_ration[%d] min_busy_ratio[%d] \n",channel,min_ap_num,min_ap_num_ration,min_busy_ratio);
	//		atbm_printk_err("i = %d , busy_ratio[%d] = %d \n",i,channel_hw_value(&sband->channels[i])-1,busy_ratio[channel_hw_value(&sband->channels[i])-1]);
			
			if(busy_ratio[channel_hw_value(&sband->channels[i])-1]<ATBM_BUSY_RATIO_MIN){

				if(results->weight[channel_hw_value(&sband->channels[i])-1]<=min_ap_num){
					if(results->weight[channel_hw_value(&sband->channels[i])-1]==min_ap_num){
						if(busy_ratio[channel_hw_value(&sband->channels[i])-1]<=min_ap_num_ration){
							min_ap_num = results->weight[channel_hw_value(&sband->channels[i])-1];
							channel = channel_hw_value(&sband->channels[i]);
							min_ap_num_ration = busy_ratio[channel_hw_value(&sband->channels[i])-1];
						}
					}else {
						min_ap_num = results->weight[channel_hw_value(&sband->channels[i])-1];
						channel = channel_hw_value(&sband->channels[i]);
						min_ap_num_ration = busy_ratio[channel_hw_value(&sband->channels[i])-1];
					}
				}
				
			}else if(min_ap_num == (u32)(-1)){
				if(busy_ratio[channel_hw_value(&sband->channels[i])-1]<min_busy_ratio){
					min_busy_ratio = busy_ratio[channel_hw_value(&sband->channels[i])-1];
					channel = channel_hw_value(&sband->channels[i]);
				}
			}
		}			
	}

	if(channel == 0){
		//WARN_ON(channel == 0);
		atbm_printk_err("auto select fail! \n");
		goto err;
	}
	atbm_printk_debug("auto_select channel %d\n",channel);
	memcpy(results->busy_ratio,busy_ratio,IEEE80211_ATBM_MAX_SCAN_CHANNEL_INDEX);
	results->susgest_channel = channel;
	ieee80211_scan_cca_val_put(&local->hw);
	return true;
err:
	ieee80211_scan_cca_val_put(&local->hw);
	return false;
}
#ifdef CONFIG_ATBM_MONITOR_SPECIAL_MAC
bool atbm_internal_mac_monitor(struct ieee80211_hw *hw,struct ieee80211_internal_mac_monitor *monitor)
{
	
	struct atbm_common *hw_priv = (struct atbm_common *)hw->priv;
	char* cmd = NULL;
	int len = 0;
	bool ret = true;

	cmd = atbm_kzalloc(ATBM_WSM_CMD_LEN,GFP_KERNEL);

	if(cmd == NULL){
		ret = false;
		goto exit;
	}
	
	if(monitor->flags & (IEEE80211_INTERNAL_MAC_MONITOR_START | IEEE80211_INTERNAL_MAC_MONITOR_STOP)){

		atbm_printk_err("mac_monitor:enable(%d),mac[%pM]\n",__func__,
						!!(monitor->flags&IEEE80211_INTERNAL_MAC_MONITOR_START),
						monitor->mac);
		len = scnprintf(cmd, ATBM_WSM_CMD_LEN, ATBM_WSM_MONITOR_MAC,monitor->index,
						!!(monitor->flags&IEEE80211_INTERNAL_MAC_MONITOR_START),
						monitor->mac[0],monitor->mac[1],
						monitor->mac[2],monitor->mac[3],
						monitor->mac[4],monitor->mac[5]);

		if(len<=0){
			ret = false;
			goto exit;
		}

		if(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, len+1, 0) < 0){
			ret = false;
			goto exit;
		}
	}

	if(monitor->flags & IEEE80211_INTERNAL_MAC_MONITOR_RESULTS){
		
		int i = 0;
		if(wsm_read_mib(hw_priv,WSM_MIB_ID_GET_MONITOR_MAC_STATUS,cmd,ATBM_WSM_CMD_LEN,0) != 0){
			ret = false;
			goto exit;
		}

		for (i = 0;i<IEEE80211_INTERNAL_MAC_MONITOR_RESULTS;i++){
			monitor->reults[i].found     = 	*cmd++;
			monitor->reults[i].rssi      = 	*cmd++;
			monitor->reults[i].forcestop =	*cmd++;
			monitor->reults[i].used   	 =	*cmd++;
			monitor->reults[i].index     =  *cmd++;
			monitor->reults[i].enabled   =  *cmd++; 
			memcpy(monitor->reults[i].mac,cmd,6); cmd += 6;
			monitor->reults[i].delta_time = __le32_to_cpu(*((u32*)cmd)); cmd += 4;

			if(monitor->reults[i].used == 0){
				monitor->reults[i].used = 1;
				break;
			}
		}
	}
	
exit:
	if(cmd)
		atbm_kfree(cmd);
	return ret;
}
#endif
bool atbm_internal_request_chip_cap(struct ieee80211_hw *hw,struct ieee80211_internal_req_chip *req)
{
	struct atbm_common *hw_priv = (struct atbm_common *)hw->priv;

	if(req->flags & IEEE80211_INTERNAL_REQ_CHIP_FLAGS__CHIP_VER){
		if(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_EFUSE8){
			req->chip_version = chip_6038;
		}else if(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_EFUSEI){
			req->chip_version = chip_6032i;
		}else if(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_EFUSEB){
			req->chip_version = chip_101B;
		}else {
			req->chip_version = chip_6032i;
		}
	}

	/*other code */

	return true;
}
#ifdef CONFIG_ATBM_SUPPORT_AP_CONFIG
bool atbm_internal_update_ap_conf(struct ieee80211_sub_if_data *sdata,
									     struct ieee80211_internal_ap_conf *conf_req,bool clear)
{
	
	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_scan("%s:%d\n",__func__,__LINE__);
		goto err;
	}

	if(conf_req&&conf_req->channel){
		if(ieee8011_channel_valid(&sdata->local->hw,(int)conf_req->channel) == false){
			goto err;
		}
	}

	return ieee80211_update_ap_config(sdata,conf_req,clear);
err:
	return false;
}
#endif
int atbm_internal_addr_read_bit(struct atbm_common *hw_priv,u32 addr,u8 endBit,
	u8 startBit,u32 *data )
{                                                              
	u32	reg_val=0;                                        
	u32 regmask=0;
	int ret = 0;
	
	ret=atbm_direct_read_reg_32(hw_priv,addr,&reg_val); 
	if(ret<0){
		goto rw_end;
	}                             
	regmask = ~((1<<startBit) -1);                               
	regmask &= ((1<<endBit) -1)|(1<<endBit);                     
	reg_val &= regmask;                                      
	reg_val >>= startBit; 
	
	*data = reg_val;
rw_end:
	return ret;
}   

int atbm_internal_addr_write_bit(struct atbm_common *hw_priv,u32 addr,u8 endBit,
											u8 startBit,u32 data)
{                                                              
	u32	reg_val=0;                                        
	u32 regmask=0;
	int ret = 0;
	
	ret = atbm_direct_read_reg_32(hw_priv,addr,&reg_val); 
	
	if(ret<0){
		atbm_printk_err("%s:read err\n",__func__);
		goto rw_end;
	} 
	atbm_printk_err("%s:ret(%d)\n",__func__,ret);
	regmask = ~((1<<startBit) -1);                               
	regmask &= ((1<<endBit) -1)|(1<<endBit);                     
	reg_val &= ~regmask;                                      
	reg_val |= (data <<startBit)&regmask;                     
	ret = atbm_direct_write_reg_32(hw_priv,addr,reg_val);
	
	if(ret<0)
	{
		atbm_printk_err("%s:write err\n",__func__);
		goto rw_end;
	}
	
	if(ret)
		ret = 0;
rw_end:
	atbm_printk_err("%s:ret(%d)\n",__func__,ret);

	return ret;
}  

static int atbm_internal_gpio_set(struct atbm_common *hw_priv,struct atbm_ctr_addr *gpio_addr)
{
	unsigned int status = -1; 
	
	if(atbm_bh_is_term(hw_priv)){
		atbm_printk_err("%s:atbm term\n",__func__);
		goto exit;
	}
	
	status = atbm_internal_addr_write_bit(hw_priv,gpio_addr->base_addr,
			gpio_addr->start_bit+gpio_addr->width,gpio_addr->start_bit,gpio_addr->val);
exit:
	return status;
}

static int atbm_internal_gpio_get(struct atbm_common *hw_priv,struct atbm_ctr_addr *gpio_addr)
{
	unsigned int status = -1; 
	
	if(atbm_bh_is_term(hw_priv)){
		atbm_printk_err("%s:atbm term\n",__func__);
		goto exit;
	}
	
	status = atbm_internal_addr_read_bit(hw_priv,gpio_addr->base_addr,
			gpio_addr->start_bit+gpio_addr->width-1,gpio_addr->start_bit,&gpio_addr->val);
exit:
	return status;
}

static struct atbm_gpio_config *atbm_internal_gpio_reqest(struct atbm_common *hw_priv,int gpio)
{
	int i = 0;
	struct atbm_gpio_config *gpio_dev = NULL;
	
	for(i = 0;i < ARRAY_SIZE(atbm_gpio_table);i++){
		gpio_dev = &atbm_gpio_table[i];
		if(gpio_dev->gpio == gpio){
			return gpio_dev;
		}
	}

	return NULL;
	
}
bool atbm_internal_gpio_config(struct atbm_common *hw_priv,int gpio,bool dir ,bool pu,bool default_val)
{
	struct atbm_gpio_config *gpio_dev = NULL;
	bool ret = true;
	int status = -1;
	
	gpio_dev = atbm_internal_gpio_reqest(hw_priv,gpio);

	if(gpio_dev == NULL){
		atbm_printk_err("%s:gpio (%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	gpio_dev->fun_ctrl.val = 3;
	gpio_dev->dir_ctrl.val = dir == true ? 1:0;
	gpio_dev->pup_ctrl.val = pu  == true ? 1:0;
	gpio_dev->pdu_ctrl.val = pu  == false ? 1:0;

	status = atbm_internal_gpio_set(hw_priv,&gpio_dev->fun_ctrl);

	if(status){
		atbm_printk_err("%s:gpio function(%d)(%d) is err\n",__func__,gpio,status);
		ret =  false;
		goto exit;
	}

	status = atbm_internal_gpio_set(hw_priv,&gpio_dev->dir_ctrl);
	
	if(status){
		atbm_printk_err("%s:gpio dir(%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	status = atbm_internal_gpio_set(hw_priv,&gpio_dev->pup_ctrl);
	
	if(status){
		atbm_printk_err("%s:gpio pup(%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	status = atbm_internal_gpio_set(hw_priv,&gpio_dev->pup_ctrl);
	
	if(status){
		atbm_printk_err("%s:gpio pdu(%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	if(dir == true){
		gpio_dev->out_val.val = default_val == true ? 1:0;
		status = atbm_internal_gpio_set(hw_priv,&gpio_dev->out_val);
		if(status){
			atbm_printk_err("%s:gpio out(%d) is err\n",__func__,gpio);
			ret =  false;
			goto exit;
		}
	}

	gpio_dev->flags = ATBM_GPIO_CONFIG__FUNCTION_CONFIGD;

	if(dir == true)
		gpio_dev->flags |= ATBM_GPIO_CONFIG__OUTPUT;
	else
		gpio_dev->flags |= ATBM_GPIO_CONFIG__INPUT;

	if(pu)
		gpio_dev->flags |= ATBM_GPIO_CONFIG__PUP;
	else
		gpio_dev->flags |= ATBM_GPIO_CONFIG__PUD;
exit:	
	return ret;
}

bool atbm_internal_gpio_output(struct atbm_common *hw_priv,int gpio,bool set)
{
	struct atbm_gpio_config *gpio_dev = NULL;
	bool ret =true;
	
	gpio_dev = atbm_internal_gpio_reqest(hw_priv,gpio);

	if(gpio_dev == NULL){
		atbm_printk_err("%s:gpio (%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	if(!(gpio_dev->flags & ATBM_GPIO_CONFIG__FUNCTION_CONFIGD)){
		atbm_printk_err("%s:gpio (%d) is not configed\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	if(!(gpio_dev->flags & ATBM_GPIO_CONFIG__OUTPUT)){
		atbm_printk_err("%s:gpio (%d) is not output mode\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	gpio_dev->out_val.val = set == true ? 1:0;
	
	if(atbm_internal_gpio_set(hw_priv,&gpio_dev->out_val)){
		atbm_printk_err("%s:gpio out(%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}
exit:
	return ret;
}

bool atbm_internal_gpio_input(struct atbm_common *hw_priv,int gpio,bool *set)
{
	struct atbm_gpio_config *gpio_dev = NULL;
	bool ret =true;
	
	gpio_dev = atbm_internal_gpio_reqest(hw_priv,gpio);

	if(gpio_dev == NULL){
		atbm_printk_err("%s:gpio (%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	if(!(gpio_dev->flags & ATBM_GPIO_CONFIG__FUNCTION_CONFIGD)){
		atbm_printk_err("%s:gpio (%d) is not configed\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	if(!(gpio_dev->flags & ATBM_GPIO_CONFIG__INPUT)){
		atbm_printk_err("%s:gpio (%d) is not input mode\n",__func__,gpio);
		ret =  false;
		goto exit;
	}
	
	if(atbm_internal_gpio_get(hw_priv,&gpio_dev->in_val)){
		atbm_printk_err("%s:gpio out(%d) is err\n",__func__,gpio);
		ret =  false;
		goto exit;
	}

	*set = gpio_dev->in_val.val ? true:false;
exit:
	return ret;
}
/*
WSM_EDCA_SET(&priv->edca, queue, params->aifs,
                                params->cw_min, params->cw_max, params->txop, 0xc8,
                                params->uapsd);

*/
bool atbm_internal_edca_update(struct ieee80211_sub_if_data *sdata,int queue,int aifs,int cw_win,int cw_max,int txop)
{
	bool ret = false;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_scan("%s:%d\n",__func__,__LINE__);
		goto exit;
	}

	if(atomic_read(&priv->enabled) == 0){
		atbm_printk_err("%s:disabled\n",__func__);
		goto exit;
	}

	WSM_EDCA_SET(&priv->edca, queue, aifs,
                 cw_win, cw_max, txop, 0xc8,
                 priv->edca.params[queue].uapsdEnable);
	ret = wsm_set_edca_params(priv->hw_priv, &priv->edca, priv->if_id);
	if (ret) {
		atbm_printk_err("%s:wsm_set_edca_params\n",__func__);
		goto exit;
	}

	ret = true;
exit:
	
	return ret;
}


extern void atbm_wifi_cfo_set(int status);

int open_auto_cfo(struct atbm_common *hw_priv,int open)
{
	char *ppm_buf="cfo 1";
	char *ppm_buf_close="cfo 0";
	int err = 0;
	if(open){
		err = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, ppm_buf, 6, 0);
		
	}else{
		err = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, ppm_buf_close, 6, 0);
	}
	
	if(err < 0){
		atbm_printk_err(" cfo fail!!!. \n");
	}else
		atbm_wifi_cfo_set(open);
	
	return err;
}

struct atbm_vendor_cfg_ie private_ie;


int atbm_internal_recv_6441_vendor_ie(struct atbm_vendor_cfg_ie *recv_ie)
{
	
//	if(recv_ie){
	//	if(memcmp(recv_ie,&private_ie,sizeof(struct atbm_vendor_cfg_ie))){
			memcpy(&private_ie,recv_ie,sizeof(struct atbm_vendor_cfg_ie));
			return 0;
	//	}
//	}
//	return -1;
}
struct atbm_vendor_cfg_ie * atbm_internal_get_6441_vendor_ie(void)
{
	struct atbm_vendor_cfg_ie ie;
	memset(&ie,0,sizeof(struct atbm_vendor_cfg_ie));
	if(memcmp(&ie,&private_ie,sizeof(struct atbm_vendor_cfg_ie)) == 0)
		return NULL;

	return &private_ie;


}


#ifdef CONFIG_CFG80211_INTERNAL_REGDB
#include "country_code.h"
int atbm_set_country_code_to_cfg80211(struct ieee80211_local *local,char *country)
{

	int i = 0,found = 0;
	if(!local || !country){
		atbm_printk_err("%s %d : %s,%s\n",__func__,__LINE__,local==NULL?"local is NULL":" ",country?" ":"country is NULL");
		return -1;
	}
	//country_code = atbm_country_code;
	for(i = 0;memcmp(atbm_country_code[i],"00",2)!=0;i++){
		if(memcmp(country,atbm_country_code[i],2) == 0){
			found = 1;
			break;	
		}
	}

	if(found == 0){
		atbm_printk_err("unknow country code (%c%c) \n",country[0],country[1]);
		return -1;
	}
	
	if(regulatory_hint(local->hw.wiphy,country) != 0){
		atbm_printk_err("not set country code to cfg80211\n");
		return -1;
	}
	
	memcpy(local->country_code,country,2);
	return 0;
}
#endif

u32 MyRand(void)
{
	u32 random_num = 0;
	u32 randseed = 0;	

#if (LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0))
	randseed = ktime_get_seconds();
#else
	struct timex txc;
	do_gettimeofday(&(txc.time));
	//randseed = jiffies;
	randseed = txc.time.tv_sec;
#endif
	random_num = randseed * 1103515245 + 12345;
	return ((random_num/65536)%32768);
}

int MacStringToHex(char *mac, u8  *umac)
{
	int i = 0, j = 0;
	unsigned char d = 0;
	char ch = 0,buffer[12] = {0};

	if(mac)
		memcpy(buffer, mac, strlen(mac));

    for (i=0;i<12;i++)
    {
        ch = buffer[i];

        if (ch >= '0' && ch <= '9')
        {
            d = (d<<4) | (ch - '0');
        }
        else if (ch >= 'a' && ch <= 'f')
        {
            d = (d<<4) | (ch - 'a' + 10);
        }
        else if (ch >= 'A' && ch <= 'F')
        {
            d = (d<<4) | (ch - 'A' + 10);
        }
		if((i%2 == 1)){
			umac[j++] = d;
			d = 0;
		}
    }

    return 0;
}

extern u8 ETF_bStartTx;
extern u8 ETF_bStartRx;
extern u8 ucWriteEfuseFlag;
extern int atbm_test_rx_cnt;
extern int txevm_total;
extern u32 chipversion;
extern struct rxstatus_signed gRxs_s;
char ch_and_type[20];
extern int wsm_start_tx(struct atbm_common *hw_priv, struct ieee80211_vif *vif);
extern int wsm_stop_tx(struct atbm_common *hw_priv);
extern int wsm_start_tx_v2(struct atbm_common *hw_priv, struct ieee80211_vif *vif );
#define CHIP_VERSION_REG 0x0acc017c //chip version reg address


#define DCXO_CODE_MINI		0//24//0
#define DCXO_CODE_MAX		127//38//63
extern  u8 CodeStart;
extern u8 CodeEnd;
extern struct etf_test_config etf_config;

//config etf test arguments by config_param.txt
void etf_PT_test_config(char *param)
{
	int Freq = 0;
	int txEvm = 0;
	int rxEvm = 0;
	int rxEvmthreshold = 0;
	int txEvmthreshold = 0;
	int Txpwrmax = 0;
	int Txpwrmin = 0;
	int Rxpwrmax = 0;
	int Rxpwrmin = 0;
	int rssifilter = 0;
	int cableloss = 0;
	int default_dcxo = 0;
	int noFreqCali = 0;
	char mac[12] = {0};
	int dcxo_max_min = 0;
	
	memset(&etf_config, 0, sizeof(struct etf_test_config));

	if(strlen(param) != 0)
	{
		atbm_printk_always("<USE CONFIG FILE>\n");
		atbm_printk_always("param:%s\n", param);
		sscanf(param, "cfg:%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s", 
			&Freq, &txEvm, &rxEvm, &txEvmthreshold,&rxEvmthreshold,&Txpwrmax, 
			&Txpwrmin, &Rxpwrmax, &Rxpwrmin, &rssifilter, &cableloss, &default_dcxo,&noFreqCali, &dcxo_max_min, mac);
		etf_config.freq_ppm = Freq;
		etf_config.txevm = (txEvm?txEvm:65536); //txevm filter
		etf_config.rxevm = (rxEvm?rxEvm:65536); //rxevm filter
		etf_config.txevmthreshold = txEvmthreshold;
		etf_config.rxevmthreshold = rxEvmthreshold;
		etf_config.txpwrmax = Txpwrmax;
		etf_config.txpwrmin = Txpwrmin;
		etf_config.rxpwrmax = Rxpwrmax;
		etf_config.rxpwrmin = Rxpwrmin;
		etf_config.rssifilter = rssifilter;
		etf_config.cableloss = (cableloss?cableloss:30)*4;	
		etf_config.default_dcxo = default_dcxo;
		etf_config.noFfreqCaliFalg = noFreqCali;
		dcxo_max_min &= 0xffff;
		etf_config.dcxo_code_min = dcxo_max_min & 0xff;
		etf_config.dcxo_code_max = (dcxo_max_min >> 8) & 0xff;

		if(etf_config.dcxo_code_min < DCXO_CODE_MAX)
			CodeStart = etf_config.dcxo_code_min;
		else
			CodeStart = DCXO_CODE_MINI;
		if((etf_config.dcxo_code_max > DCXO_CODE_MINI) && (etf_config.dcxo_code_max <= DCXO_CODE_MAX))
			CodeEnd = etf_config.dcxo_code_max;
		else
			CodeEnd = DCXO_CODE_MAX;
		
		if(strlen(mac) == 12){
			etf_config.writemacflag = 1;
			MacStringToHex(mac, etf_config.writemac);
		}
	}
	else
	{
		etf_config.freq_ppm = 7000;
		etf_config.rxevm = (rxEvm?rxEvm:65536);
		etf_config.rssifilter = -100;
		etf_config.txevm = (txEvm?txEvm:65536);
		etf_config.txevmthreshold = 400;
		etf_config.rxevmthreshold = 400;
		etf_config.cableloss = 30*4;
		CodeStart = DCXO_CODE_MINI;
		CodeEnd = DCXO_CODE_MAX;
	}

	etf_config.featureid = MyRand();
	atbm_printk_always("featureid:%d\n", etf_config.featureid);
	atbm_printk_always("Freq:%d,txEvm:%d,rxEvm:%d,txevmthreshold:%d,rxevmthreshold:%d,Txpwrmax:%d,Txpwrmin:%d,Rxpwrmax:%d,Rxpwrmin:%d,rssifilter:%d,cableloss:%d,default_dcxo:%d,noFreqCali:%d",
		etf_config.freq_ppm,etf_config.txevm,etf_config.rxevm,etf_config.txevmthreshold,etf_config.rxevmthreshold,
		etf_config.txpwrmax,etf_config.txpwrmin,etf_config.rxpwrmax,
		etf_config.rxpwrmin,etf_config.rssifilter,etf_config.cableloss,etf_config.default_dcxo,
		etf_config.noFfreqCaliFalg);
	atbm_printk_always("dcxomin:%d,dcxomax:%d", etf_config.dcxo_code_min, etf_config.dcxo_code_max);
	if(strlen(mac) == 12){
		atbm_printk_always("WRITE MAC:%02X%02X%02X%02X%02X%02X\n", 
					etf_config.writemac[0],etf_config.writemac[1],etf_config.writemac[2],
					etf_config.writemac[3],etf_config.writemac[4],etf_config.writemac[5]);
		}
	atbm_printk_always("\n");
}
//get chip version funciton
u32 GetChipVersion(struct atbm_common *hw_priv)
{	
#ifndef SPI_BUS
	u32 uiRegData;
	atbm_direct_read_reg_32(hw_priv, CHIP_VERSION_REG, &uiRegData);
	//hw_priv->sbus_ops->sbus_read_sync(hw_priv->sbus_priv,CHIP_VERSION_REG,&uiRegData,4);	
	
	return uiRegData;
#else
	return 0;
#endif
}

#ifdef CONFIG_ATBM_ETF_OLD

int atbm_internal_start_tx(struct ieee80211_sub_if_data *sdata,struct ieee80211_internal_etf_request  *tx_param)
{
	int i = 0;
	u32 rate;
	int etf_v2 = 0;
	u8 ucDbgPrintOpenFlag = 1;
	struct atbm_vif *vif;
//	char threshold_param[100] = {0};
	int channel;
	int band_value;
	int is_40M;
	int len;
	int greedfiled;
	u8 precomp_sel = 0;
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	memset(&gRxs_s, 0, sizeof(struct rxstatus_signed));

	chipversion = GetChipVersion(hw_priv);
	atbm_printk_wext("chipversion:0x%x\n", chipversion);
	if(ETF_bStartTx || ETF_bStartRx){
		
		if(ETF_bStartTx){
			atbm_internal_stop_tx(sdata);
			msleep(500);
		}else{
			atbm_printk_err("Error! already start_tx, please stop_rx first!\n");
			return 0;
		}
		
	}
	
	channel = tx_param->channel;
	band_value = tx_param->rate;
	is_40M = tx_param->channel_type;
	len = tx_param->len;
	greedfiled = tx_param->greedfiled;

	if(channel <= 0 || channel > 14){
		atbm_printk_err("invalid channel!channel(%d)\n",channel);
		return -EINVAL;
	}
	//check rate 
		switch(band_value){
			case 10: rate = WSM_TRANSMIT_RATE_1;//ucDbgPrintOpenFlag = 0;
			break;
			case 20: rate = WSM_TRANSMIT_RATE_2;//ucDbgPrintOpenFlag = 0;
			break;
			case 55: rate = WSM_TRANSMIT_RATE_5;//ucDbgPrintOpenFlag = 0;
			break;
			case 110: rate = WSM_TRANSMIT_RATE_11;//ucDbgPrintOpenFlag = 0;
			break;
			case 60: rate = WSM_TRANSMIT_RATE_6;
			break;
			case 90: rate = WSM_TRANSMIT_RATE_9;
			break;
			case 120: rate = WSM_TRANSMIT_RATE_12;
			break;
			case 180: rate = WSM_TRANSMIT_RATE_18;
			break;
			case 240: rate = WSM_TRANSMIT_RATE_24;
			break;
			case 360: rate = WSM_TRANSMIT_RATE_36;
			break;
			case 480: rate = WSM_TRANSMIT_RATE_48;
			break;
			case 540: rate = WSM_TRANSMIT_RATE_54;
			break;
			case 65: rate = WSM_TRANSMIT_RATE_HT_6;
			break;
			case 130: rate = WSM_TRANSMIT_RATE_HT_13;
			break;
			case 195: rate = WSM_TRANSMIT_RATE_HT_19;
			break;
			case 260: rate = WSM_TRANSMIT_RATE_HT_26;
			break;
			case 390: rate = WSM_TRANSMIT_RATE_HT_39;
			break;
			case 520: rate = WSM_TRANSMIT_RATE_HT_52;
			break;
			case 585: rate = WSM_TRANSMIT_RATE_HT_58;
			break;
			case 650: rate = WSM_TRANSMIT_RATE_HT_65;
			break;
			default:
				atbm_printk_err("invalid rate!\n");
				return -EINVAL;
				
		}

	if((is_40M == 1 )&& (rate < WSM_TRANSMIT_RATE_HT_6)){
		atbm_printk_err("invalid 40M rate\n");
		return -EINVAL;
	}	
	if((is_40M == 1 )&& ((channel < 3)||(channel > 11))){
		atbm_printk_err("invalid 40M rate,channel value range:3~11\n");
		return -EINVAL;
	}

	if((is_40M == 1 )&&(hw_priv->chip_version == ARES_6012B) ){
		atbm_printk_err("invalid 40M rate,current chip is not support HT40!!\n");
		return -EINVAL;

	}
	
	open_auto_cfo(hw_priv,0);
	if(len == 99999){
		ucWriteEfuseFlag = 1;
		etf_v2 = 1;	
		len = hw_priv->etf_len = 1000; 
	}else if(len == 99998)
	{
		ucWriteEfuseFlag = 0;
		etf_v2 = 1;	
		len = hw_priv->etf_len = 1000; 
	}
	//Prevent USB from being unplugged suddenly in product testing
	//11b 100% duty cycle
	if((rate <= WSM_TRANSMIT_RATE_11)&&(len == 0))
	{
		len = 1000;
		if(is_40M == 1){
			is_40M = NL80211_CHAN_HT40PLUS;//
			channel -= 2;
		}

		hw_priv->etf_channel = channel;
		hw_priv->etf_channel_type = is_40M;
		hw_priv->etf_rate = rate;
		hw_priv->etf_len = len; 
		hw_priv->etf_greedfiled = greedfiled;
		
		atbm_for_each_vif(hw_priv,vif,i){
			if((vif != NULL)){
				atbm_printk_wext("*******\n");
				down(&hw_priv->scan.lock);
				WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
				mutex_lock(&hw_priv->conf_mutex);				
				ETF_bStartTx = 1;
				mutex_unlock(&hw_priv->conf_mutex);
				if(wsm_start_tx(hw_priv, vif->vif) != 0){
					up(&hw_priv->scan.lock);
					atbm_printk_err("%s:%d,wsm_start_tx error\n", __func__, __LINE__);
					goto _exit;
				}
				msleep(1000);
				wsm_oper_unlock(hw_priv);
				wsm_stop_tx(hw_priv);
				wsm_stop_scan(hw_priv,i);
		//		if(atbm_hw_cancel_delayed_work(&hw_priv->scan.timeout,true))
		//			atbm_scan_timeout(&hw_priv->scan.timeout.work);
				//up(&hw_priv->scan.lock);
				msleep(1000);
				hw_priv->etf_rate = 5;
				if(wsm_start_tx(hw_priv, vif->vif) != 0){
					up(&hw_priv->scan.lock);
					atbm_printk_err("%s:%d,wsm_start_tx error\n", __func__, __LINE__);
					goto _exit;
				}
			}
			break;
		}
	}
	else{
		//check len
		if(len < 200 || len > 1024){
			atbm_printk_err("len:%d\n", len);
			atbm_printk_err("invalid len!\n");
			
			return -EINVAL;
		}
		if(is_40M == 1){
			is_40M = NL80211_CHAN_HT40PLUS;//
			channel -= 2;
		}

		atbm_printk_wext("NL80211_CHAN_HT40PLUS:%d\n", NL80211_CHAN_HT40PLUS);

		//printk("%d, %d, %d, %d\n", channel, rate, len, is_40M);
		hw_priv->etf_channel = channel;
		hw_priv->etf_channel_type = is_40M;
		hw_priv->etf_rate = rate;
		hw_priv->etf_len = len; 
		hw_priv->etf_greedfiled = greedfiled;
		atbm_printk_always("tx chan[%d] rate[%d] len[%d] BW[%d] greedfiled[%d] precomp_sel[%d]\n",
			channel, rate, len, is_40M, greedfiled, precomp_sel);
		
		atbm_for_each_vif(hw_priv,vif,i){
			if((vif != NULL)){

				down(&hw_priv->scan.lock);
		
				if(!etf_v2)
				{
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
				}
				mutex_lock(&hw_priv->conf_mutex);
				
				if(etf_v2){
					atbm_test_rx_cnt = 0;
					txevm_total = 0;
					if(etf_v2)
					{
						hw_priv->bStartTx = 1;
						hw_priv->bStartTxWantCancel = 1;
						hw_priv->etf_test_v2 =1;
					}
					
					etf_PT_test_config(tx_param->threshold_param);
					if(chipversion == 0x49)
						GetChipCrystalType(hw_priv);
				
					if(wsm_start_tx_v2(hw_priv, vif->vif) != 0)
					{
						up(&hw_priv->scan.lock);
						atbm_printk_err("%s:%d,wsm_start_tx_v2 error\n", __func__, __LINE__);
					}
				}
				else
				{
					ETF_bStartTx = 1;
					if((rate > WSM_TRANSMIT_RATE_11) && (is_40M == 0) && (channel == 13))
						precomp_sel = tx_param->precomp_sel;
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_SET_PRE_COMPENSATION,
						&precomp_sel, sizeof(precomp_sel), vif->if_id));
					
					if(wsm_start_tx(hw_priv, vif->vif) != 0)
					{
						up(&hw_priv->scan.lock);
						atbm_printk_err("%s:%d,wsm_start_tx error\n", __func__, __LINE__);
					}
				}
				mutex_unlock(&hw_priv->conf_mutex);
				break;
			}
		}
	}
_exit:
	return 0;

}


int atbm_internal_stop_tx(struct ieee80211_sub_if_data *sdata)
{
	int i = 0;
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	
	msleep(500);
	if(0 == ETF_bStartTx){
		atbm_printk_err("please start start_rx first,then stop_rx\n");
		return -EINVAL;
	}
	open_auto_cfo(hw_priv,1);
	mutex_lock(&hw_priv->conf_mutex);
	ETF_bStartTx = 0;
	mutex_unlock(&hw_priv->conf_mutex);
	//./iwpriv wlan0 fwdbg 0
	
	atbm_for_each_vif(hw_priv,vif,i){
		if((vif != NULL)){
			
			wsm_oper_unlock(hw_priv);
	//		atbm_printk_err("%s %d \n",__func__,__LINE__);
			wsm_stop_tx(hw_priv);
			wsm_stop_scan(hw_priv,i);
	//		atbm_printk_err("%s %d \n",__func__,__LINE__);
	//		if(atbm_hw_cancel_delayed_work(&hw_priv->scan.timeout,true))
	//			atbm_scan_timeout(&hw_priv->scan.timeout.work);
	//		if (unlikely(down_trylock(&hw_priv->scan.lock))){
	//		}
			up(&hw_priv->scan.lock);
//	atbm_printk_err("%s %d \n",__func__,__LINE__);
	//		break;
		}
	}
	
	//printk("%s %d\n", __FUNCTION__, __LINE__)
	return 0;
}
#else


int atbm_ioctl_start_txv1_process(struct ieee80211_hw *hw,struct ieee80211_vif *vif,
					   enum ieee80211_etf_request_action action,
					   struct ieee80211_scan_req_wrap *req_wrap,struct sk_buff *skb)
{
	struct atbm_common *hw_priv = hw->priv;
	struct atbm_vif *priv = ABwifi_get_vif_from_ieee80211(vif);
	struct ieee80211_internal_etf_request *etf = req_wrap->etf;
	u8 ucDbgPrintOpenFlag = 1;

	switch(action){
	case EFT_REQUEST_ACTION_START:
		atbm_printk_wext("[ETF V1]:start\n");
		WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), priv->if_id));
		hw_priv->scan.req = req_wrap->req;
		hw_priv->scan.req_wrap = req_wrap;
		hw_priv->scan.if_id = priv->if_id;
		hw_priv->scan.etf   = etf;

		hw_priv->etf_channel = channel_hw_value(req_wrap->req->channels[0]);
		hw_priv->etf_channel_type = etf->channel_type;
		hw_priv->etf_rate = etf->rate;
		hw_priv->etf_len = etf->len; 
		hw_priv->etf_greedfiled = etf->greedfiled;
		atomic_set(&hw_priv->scan.in_progress, 1);
		hw_priv->scan.wait_complete = 1;
		
		if(wsm_start_tx(hw_priv, vif)){
			atomic_set(&hw_priv->scan.in_progress, 0);
			hw_priv->scan.wait_complete = 0;
		}
		return 0;
	case EFT_REQUEST_ACTION_SCAN_COMP:
		atbm_printk_wext("[ETF V1]:comp\n");
		atomic_set(&hw_priv->scan.in_progress, 1);
		hw_priv->scan.wait_complete = 1;
		if(wsm_start_scan_etf(hw_priv,vif)){
			atomic_set(&hw_priv->scan.in_progress, 0);
			hw_priv->scan.wait_complete = 0;
		}
		return 0;
	case EFT_REQUEST_ACTION_SCAN_FORCE_STOP:
		atbm_printk_wext("[ETF V1]:stop start\n");
		ucDbgPrintOpenFlag = 0;
		WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), priv->if_id));
		
		if(atomic_xchg(&hw_priv->scan.in_progress, 0)){
			atbm_printk_wext("[ETF V1]:stop scan++\n");
			wsm_stop_scan(hw_priv,priv->if_id);
			atbm_printk_wext("[ETF V1]:stop scan--\n");
		}

		if(hw_priv->scan.if_id != -1){
			wsm_stop_tx(hw_priv);
		}
		
		hw_priv->scan.req = NULL;
		hw_priv->scan.req_wrap = NULL;
		hw_priv->scan.if_id = -1;
		hw_priv->scan.etf = NULL;
		atbm_printk_wext("[ETF V1]:stop end\n");
		return 1;
	case EFT_REQUEST_ACTION_RECEIVE:
		atbm_printk_wext("[ETF V1]:receive\n");
		break;
	default:BUG_ON(1);
	}

	return 1;
}

int atbm_ioctl_start_txv2_process(struct ieee80211_hw *hw,struct ieee80211_vif *vif,
						enum ieee80211_etf_request_action action,
						struct ieee80211_scan_req_wrap *req_wrap,struct sk_buff *skb)
{
	struct atbm_common *hw_priv = hw->priv;
	struct atbm_vif *priv = ABwifi_get_vif_from_ieee80211(vif);
	struct ieee80211_internal_etf_request *etf = req_wrap->etf;
	u8 ucDbgPrintOpenFlag = 1;
	
	switch(action){
	case EFT_REQUEST_ACTION_START:
		atbm_printk_wext("[ETF V2]:start\n");
		ucDbgPrintOpenFlag = 1;
		WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), priv->if_id));
		hw_priv->scan.req = req_wrap->req;
		hw_priv->scan.req_wrap = req_wrap;
		hw_priv->scan.if_id = priv->if_id;
		hw_priv->scan.etf	= etf;

		hw_priv->etf_channel = channel_hw_value(req_wrap->req->channels[0]);
		hw_priv->etf_channel_type = etf->channel_type;
		hw_priv->etf_rate = etf->rate;
		hw_priv->etf_len = etf->len; 
		hw_priv->etf_greedfiled = etf->greedfiled;
		atomic_set(&hw_priv->scan.in_progress, 1);
		hw_priv->scan.wait_complete = 1;
		
		if(wsm_start_tx(hw_priv, vif)){
			atomic_set(&hw_priv->scan.in_progress, 0);
			hw_priv->scan.wait_complete = 0;
		}

		chipversion = GetChipVersion(hw_priv);
		atbm_test_rx_cnt = 0;
		txevm_total = 0;
		etf_PT_test_config(etf->threshold_param);
		
		if(chipversion == 0x49)
			GetChipCrystalType(hw_priv);
		
		if(wsm_start_tx_v2(hw_priv, vif) != 0){
			atomic_set(&hw_priv->scan.in_progress, 0);
			hw_priv->scan.wait_complete = 0;
			atbm_printk_err("%s:%d,wsm_start_tx_v2 error\n", __func__, __LINE__);
			return 1;
		}
		return 0;
	case EFT_REQUEST_ACTION_SCAN_COMP:
		atbm_printk_wext("[ETF V2]:comp\n");
		if(atomic_xchg(&hw_priv->scan.in_progress, 0)){
			if(etf_v2_scan_end(hw_priv,vif) == 1){
				return 0;
			}
		}
	case EFT_REQUEST_ACTION_SCAN_FORCE_STOP:
		atbm_printk_wext("[ETF V2]:stop\n");
		ucDbgPrintOpenFlag = 0;
		
		WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), priv->if_id));
		
		if(atomic_xchg(&hw_priv->scan.in_progress, 0)){
			wsm_stop_scan(hw_priv,priv->if_id);
		}

		if(hw_priv->scan.if_id != -1){
			wsm_stop_tx(hw_priv);
		}
		
		hw_priv->scan.req = NULL;
		hw_priv->scan.req_wrap = NULL;
		hw_priv->scan.if_id = -1;
		hw_priv->scan.etf = NULL;
		return 1;
	case EFT_REQUEST_ACTION_RECEIVE:
		atbm_printk_wext("[ETF V2]:receive\n");
		BUG_ON(skb == NULL);
		etf_v2_scan_rx(hw_priv,skb,0);
		return 0;
	default:BUG_ON(1);
	}

	return 1;


static bool atbm_etf_result_handle(struct ieee80211_sub_if_data *sdata,
			void *priv,struct ieee80211_internal_scan_result *result,bool finish)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_internal_etf_request *etf = (struct ieee80211_internal_etf_request *)priv;
	
	if(finish == true){
		atbm_internal_etf_request_put(etf);
		return true;
	}
	
	if(result->sta.skb){
		BUG_ON(etf->etf_process == NULL);
		etf->etf_process(&local->hw,&sdata->vif,EFT_REQUEST_ACTION_RECEIVE,&local->scan_req_wrap,result->sta.skb);
		/*
		*release skb
		*/
		atbm_dev_kfree_skb(result->sta.skb);
		result->sta.skb = NULL;
	}
	
	return true;
}
bool atbm_internal_request_etf(struct ieee80211_sub_if_data *sdata,struct ieee80211_internal_etf_request *request)
{
	bool ret = false;
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_internal_scan_request scan_request;
	u8 ch = (u8)request->channel;

	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_scan("%s:%d\n",__func__,__LINE__);
		goto exit;
	}
	/*
	*cancle scan or etf test
	*/
	ieee80211_scan_cancel(local);
	atbm_flush_workqueue(local->workqueue);
	
	mutex_lock(&local->mtx);
	__ieee80211_recalc_idle(local);
	mutex_unlock(&local->mtx);
	/*
	*not idle state,so return err
	*/
	if((local->hw.conf.flags & IEEE80211_CONF_IDLE) == 0){
		goto exit;
	}

	memset(&scan_request,0,sizeof(struct ieee80211_internal_scan_request));
	scan_request.result_handle = atbm_etf_result_handle;
	scan_request.priv          = (void *)request;
	scan_request.n_channels	   = 1;
	scan_request.channels      = &ch;
	scan_request.etf           = request;
	scan_request.req_flags     = IEEE80211_INTERNAL_SCAN_FLAGS__NEED_SKB | IEEE80211_INTERNAL_SCAN_FLAGS__ETF_REQUEST;

	atbm_internal_etf_request_get(request);
	
	if(atbm_internal_cmd_scan_triger(sdata,&scan_request) == false){
		atbm_internal_etf_request_put(request);
		atbm_printk_err("etf triger err\n");
		goto exit;
	}
	ret = true;
	atbm_flush_workqueue(local->workqueue);
exit:	
	return ret;
}
bool atbm_internal_request_etf_stop(struct ieee80211_sub_if_data *sdata)
{
	bool ret = false;
	
	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_scan("%s:%d\n",__func__,__LINE__);
		goto exit;
	}	
	if(sdata->local->scan_req_wrap.flags & IEEE80211_SCAN_REQ_ETF){
		ieee80211_scan_cancel(sdata->local);
		atbm_flush_workqueue(sdata->local->workqueue);
	}
exit:
	return ret;
}

static void atbm_internal_etf_request_free(struct kref *request_kref)
{
	struct ieee80211_internal_etf_request *request = container_of(request_kref, struct ieee80211_internal_etf_request, ref);
	atbm_printk_wext("etf_request_free[%p]\n",request);
	atbm_kfree(request);
}

struct ieee80211_internal_etf_request *atbm_internal_etf_request_alloc(size_t priv_size)
{
	struct ieee80211_internal_etf_request *request;

	request = atbm_kzalloc(sizeof(request) + priv_size, GFP_KERNEL);

	if(request == NULL)
		return NULL;

	kref_init(&request->ref);

	return request;
}

int atbm_internal_etf_request_put(struct ieee80211_internal_etf_request *request)
{
	return kref_put(&request->ref,atbm_internal_etf_request_free);
}

void atbm_internal_etf_request_get(struct ieee80211_internal_etf_request *request)
{
	kref_get(&request->ref);
}



int atbm_internal_start_tx(struct ieee80211_sub_if_data *sdata,struct ieee80211_internal_etf_request *request)
{
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int ret = 0;
	u8 precomp_sel = 0;
	
	switch(request->rate){
		case 10:  request->rate = WSM_TRANSMIT_RATE_1;break;
		case 20:  request->rate = WSM_TRANSMIT_RATE_2;break;
		case 55:  request->rate = WSM_TRANSMIT_RATE_5;break;
		case 110: request->rate = WSM_TRANSMIT_RATE_11;break;
		case 60:  request->rate = WSM_TRANSMIT_RATE_6;break;
		case 90:  request->rate = WSM_TRANSMIT_RATE_9;break;
		case 120: request->rate = WSM_TRANSMIT_RATE_12;break;
		case 180: request->rate = WSM_TRANSMIT_RATE_18;break;
		case 240: request->rate = WSM_TRANSMIT_RATE_24;break;
		case 360: request->rate = WSM_TRANSMIT_RATE_36;break;
		case 480: request->rate = WSM_TRANSMIT_RATE_48;break;
		case 540: request->rate = WSM_TRANSMIT_RATE_54;break;
		case 65:  request->rate = WSM_TRANSMIT_RATE_HT_6;break;
		case 130: request->rate = WSM_TRANSMIT_RATE_HT_13;break;
		case 195: request->rate = WSM_TRANSMIT_RATE_HT_19;break;
		case 260: request->rate = WSM_TRANSMIT_RATE_HT_26;break;
		case 390: request->rate = WSM_TRANSMIT_RATE_HT_39;break;
		case 520: request->rate = WSM_TRANSMIT_RATE_HT_52;break;
		case 585: request->rate = WSM_TRANSMIT_RATE_HT_58;break;
		case 650: request->rate = WSM_TRANSMIT_RATE_HT_65;break;
		default:
			atbm_printk_err("invalid rate(%d)!\n",rate.interger);
			ret = -EINVAL;
			goto exit;
	}

	if((request->channel_type != 0) && (request->channel_type != 1)){
		atbm_printk_err("invalid 40M or 20M %d\n",request->channel_type);
		ret = -EINVAL;
		goto exit;
	}

	if((request->greedfiled != 0) && (request->greedfiled != 1)){
		atbm_printk_err("invalid greedfiled %d\n",request->greedfiled);
		ret = -EINVAL;
		goto exit;
	}

	if((request->channel_type == 1 )&& (request->rate < WSM_TRANSMIT_RATE_HT_6)){
		atbm_printk_err("invalid 40M rate (%d)\n",request->rate);
		ret = -EINVAL;
		goto exit;
	}	
	if((request->channel_type == 1 )&& ((request->channel < 3)||(request->channel > 11))){
		atbm_printk_err("invalid 40M rate,channel value range:3~11\n");
		ret = -EINVAL;
		goto exit;
	}

	open_auto_cfo(hw_priv,0);
	request->version = 1;
	request->etf_process = atbm_ioctl_start_txv1_process;
	
	if(request->len == 99999){
		ucWriteEfuseFlag = 1;
		request->version = 2;	
		request->len = 1000;
		request->etf_process = atbm_ioctl_start_txv2_process;
	}else if(request->len == 99998){
		ucWriteEfuseFlag = 0;
		request->version = 2;	
		request->len = 1000;
		request->etf_process = atbm_ioctl_start_txv2_process;
	}
	
	if(request->channel_type == 1){
		request->channel_type = NL80211_CHAN_HT40PLUS;//
		request->channel -= 2;
	}
	atbm_printk_wext("start_tx:[%d][%d][%d][%d][%d]\n",request->channel,request->rate,request->len,request->channel_type,request->greedfiled);
	if((request->rate <= WSM_TRANSMIT_RATE_11)&&(request->len == 0)){
		
		request->len = 1000;
		
		if(atbm_internal_request_etf(sdata,request) == false){
			atbm_printk_err("start etf failed\n");
			ret = -EINVAL;
			goto exit;
		}
		
		msleep(1000);
		
		atbm_internal_request_etf_stop(sdata);
		
		request->rate = 5;
	}
	if((request->rate > WSM_TRANSMIT_RATE_11) && (request->channel_type == 0) && (request->channel == 13))
		precomp_sel = request->precomp_sel;
	WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_SET_PRE_COMPENSATION,
		&precomp_sel, sizeof(precomp_sel), -1));

	if(atbm_internal_request_etf(sdata,request) == false){
		atbm_printk_err("start etf failed\n");
		ret = -EINVAL;
		goto exit;
	}

	
exit:	
	return ret;
}


int atbm_internal_stop_tx(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	open_auto_cfo(hw_priv,1);
	return atbm_internal_request_etf_stop(sdata);
}

#endif
int atbm_internal_start_rx(struct ieee80211_sub_if_data *sdata,int channel,int is_40M)
{	
	int i = 0;
	char cmd[20] = "monitor 1 ";
	u8 ucDbgPrintOpenFlag = 1;
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	
		
	if(ETF_bStartTx || ETF_bStartRx){
			if(ETF_bStartRx){
				atbm_printk_err("start rx : %s ,stop now and change chan[%d],is_40M[%d]\n",ch_and_type,channel,is_40M);
				atbm_internal_stop_rx(sdata,NULL);
				msleep(500);
			}else{
				atbm_printk_err("Error! already ETF_bStartRx, please stop_tx first!\n");
				return 0;
			}
		}
	
	if((is_40M == 1 )&& ((channel == 1)||(channel > 11))){
	
		atbm_printk_err("invalid 40M rate\n");
		return -EINVAL;
	}
	if((is_40M == 1 )&&(hw_priv->chip_version == ARES_6012B) ){
		atbm_printk_err("invalid 40M rate,current chip is not support HT40!!\n");
	
		return -EINVAL;
	}
	open_auto_cfo(hw_priv,0);
	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
				&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
			break;
		}
	}
	sprintf(cmd,"monitor 1 %d %d",channel,is_40M);
	memset(ch_and_type, 0, 20);
	//memcpy(ch_and_type, extra, wrqu->data.length);
	sprintf(ch_and_type,"%d %d",channel,is_40M);
//	memcpy(cmd+10, extra, wrqu->data.length);
	
	atbm_printk_err("CMD:%s\n", cmd);
	i = 0;
	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			ETF_bStartRx = 1;
			
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,
				cmd, strlen(cmd)+1, vif->if_id));
			break;
		}
	}	
	return 0;
}

int atbm_internal_stop_rx(struct ieee80211_sub_if_data *sdata,fixed_freq_rx_data *rx_data)
{
	int i = 0;
	int ret = 0;
	char cmd[20] = "monitor 0 ";
	u8 ucDbgPrintOpenFlag = 0;
	u32 rx_status[3] = {0,0,0};
	u8 *status = NULL;
	int len = 0;
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	if((0 == ETF_bStartRx) || (NULL == ch_and_type)){
		atbm_printk_err("please start start_rx first,then stop_rx\n");
		return -EINVAL;
	}
	open_auto_cfo(hw_priv,1);
	ETF_bStartRx = 0;
	
	ret = wsm_read_shmem(hw_priv,(u32)RX_STATUS_ADDR,rx_status,sizeof(rx_status));

	if(ret != 0){
		atbm_printk_err("read shmem err! \n");
		ret = -EINVAL;
		goto exit;
	}
	if(rx_data){
		if(rx_data->status_data == NULL){
			status = atbm_kzalloc(512,GFP_KERNEL);
		}else
			status = rx_data->status_data;
	}else{
		status = atbm_kzalloc(512,GFP_KERNEL);
	}
	
	if(status == NULL){
		atbm_printk_err("alloc hmem err! \n");
		ret = -ENOMEM;
		goto exit;
	}
	memset(status,0,512);
	
	len = scnprintf(status,512,"rxSuccess:%d, FcsErr:%d, PlcpErr:%d\n",
	rx_status[0]-rx_status[1],rx_status[1],rx_status[2]);
	if(rx_data){
		memcpy(rx_data->status_data,status,512);
		rx_data->len = len;
	}
	memcpy(cmd+10, ch_and_type, strlen(ch_and_type));
	//printk("cmd %s\n", cmd);
	atbm_printk_always("%s:%s\n",__func__,status);
	i = 0;
	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,
				cmd, 13, vif->if_id));
			break;
		}
	}

	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
				&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
			break;
		}
	}
	ret = 0;
exit:
	if(rx_data == NULL && status){
		atbm_printk_err("%s : release status! \n",__func__);
		atbm_kfree(status);
	}
	return ret;
}


#ifdef CONFIG_ATBM_BLE
#include <linux/cdev.h>

#include <net/ndisc.h>

#define MAX_STATUS_SYNC_LSIT_CNT  		(10)


struct atbm_info {
	dev_t devid;
	struct cdev *my_cdev;
	struct class *my_class;
	struct device *my_device;
	struct atbm_common *hw_priv;
};

struct atbm_status_event {
	struct list_head link;
	struct ioctl_status_async status;
};

struct atbm_info atbm_info;
static struct fasync_struct *connect_async;
static spinlock_t s_status_queue_lock;
static struct list_head s_status_head;
static int s_cur_status_list_cnt = 0;
static u8 atbm_ioctl_data[1024];
extern char* ieee80211_ble_commb_ble_alloc_xmit(size_t len);
extern int ieee80211_ble_commb_xmit(struct ieee80211_local* local, u8* xmit, size_t xmit_len);
extern int ieee80211_ble_commb_start(struct ieee80211_local* local);
extern  int ieee80211_ble_commb_subscribe(struct ieee80211_local* local,
	int (*recv)(struct ieee80211_local* local, u8* recv, size_t recv_len, enum ieee80211_ble_msg_type msg_type));
int atbm_ble_dev_rx(u8* event_buffer, size_t event_len);
extern int ieee80211_ble_commb_unsubscribe(struct ieee80211_local* local);
extern int ieee80211_ble_commb_stop(struct ieee80211_local* local);
extern struct atbm_common* g_hw_priv;

#ifdef CONFIG_ATBM_BLE_ADV_COEXIST

int atbm_ioctl_ble_adv_coexit_start(u8* data)
{
	struct ioctl_ble_start* ble_start = (struct ioctl_ble_start*)data;
	struct wsm_ble_msg_coex_start ble_coex = { 0 };

	if ((ble_start->ble_adv == 0) && (ble_start->ble_scan == 0)) {
		atbm_printk_err("both adv and scan is close!\n");
		return -1;
	}

	if ((ble_start->ble_scan) && (ble_start->ble_scan_win == 0)) {
		atbm_printk_err("ble scan enable, but scan_win is 0!\n");
		return -1;
	}

	if ((ble_start->ble_adv_chan != 0) && (ble_start->ble_adv_chan >= 37)
		&& (ble_start->ble_adv_chan <= 39)) {
		ble_coex.chan_flag |= BIT(ble_start->ble_adv_chan - 37);
	}

	if ((ble_start->ble_scan_chan != 0) && (ble_start->ble_scan_chan >= 37)
		&& (ble_start->ble_scan_chan <= 39)) {
		ble_coex.chan_flag |= BIT(ble_start->ble_scan_chan - 37 + 3);
	}

	if (ble_start->ble_adv) {
		ble_coex.coex_flag |= BIT(0);
	}

	if (ble_start->ble_scan) {
		ble_coex.coex_flag |= BIT(1);
	}

	ble_coex.interval = ble_start->ble_interval;
	ble_coex.scan_win = ble_start->ble_scan_win;
	ble_coex.ble_id = BLE_MSG_COEXIST_START;
	atbm_printk_init("atbm_ioctl_ble_adv_coexit_start\n");
	return wsm_ble_msg_coexist_start(atbm_info.hw_priv, &ble_coex, 0);
}

int atbm_ioctl_ble_adv_coexit_stop(u8* data)
{
	struct wsm_ble_msg ble_coex = { 0 };
	ble_coex.ble_id = BLE_MSG_COEXIST_STOP;
	return wsm_ble_msg_coexist_stop(atbm_info.hw_priv, &ble_coex, 0);
}
int atbm_ioctl_ble_set_adv_data(u8* data)
{
	struct ioctl_ble_adv_data* adv_data = (struct ioctl_ble_adv_data*)data;
	struct wsm_ble_msg_adv_data ble_adv_data = { 0 };

	memcpy(&ble_adv_data.mac[0], adv_data, sizeof(struct ioctl_ble_adv_data));
	ble_adv_data.ble_id = BLE_MSG_SET_ADV_DATA;
	return wsm_ble_msg_set_adv_data(atbm_info.hw_priv, &ble_adv_data, 0);
}

int atbm_ioctl_ble_adv_resp_start(u8* data)
{
	struct ioctl_ble_adv_resp_start* ble_start = (struct ioctl_ble_adv_resp_start*)data;
	struct wsm_ble_msg_adv_resp_start ble_adv_resp_msg = { 0 };


	ble_adv_resp_msg.interval = ble_start->ble_interval;
	ble_adv_resp_msg.ble_id = BLE_MSG_ADV_RESP_MODE_START;
	return wsm_ble_msg_set_adv_data(atbm_info.hw_priv, (struct wsm_ble_msg_adv_data*)&ble_adv_resp_msg, 0);
}

int atbm_ioctl_ble_set_resp_data(u8* data)
{
	struct ioctl_ble_resp_data* resp_data = (struct ioctl_ble_resp_data*)data;
	struct wsm_ble_msg_resp_data ble_resp_data = { 0 };

	memcpy(&ble_resp_data.resp_data_len, resp_data, sizeof(struct ioctl_ble_resp_data));
	ble_resp_data.ble_id = BLE_MSG_SET_RESP_DATA;
	return wsm_ble_msg_set_adv_data(atbm_info.hw_priv, (struct wsm_ble_msg_adv_data*)&ble_resp_data, 0);
}
#endif//#ifdefCONFIG_ATBM_BLE_ADV_COEXISTstatic int atbm_ioctl_notify_add(u8 type, u8 driver_mode, u8 *event_buffer, u16 event_len)
static int atbm_ioctl_notify_add(u8 type, u8 driver_mode, u8 *event_buffer, u16 event_len)
{
	int first;
	struct atbm_status_event *event = NULL;

	if (atbm_info.hw_priv == NULL){
		atbm_printk_err("%s: atbm ioctl is not open.\n", __func__);
		return -1;
	}
	
	if (s_cur_status_list_cnt >= MAX_STATUS_SYNC_LSIT_CNT){
		atbm_printk_err("%s: status event list is full.\n", __func__);
		return -1;
	}

	if(event_len > MAX_SYNC_EVENT_BUFFER_LEN){
		atbm_printk_err("%s: event_len is overflow.\n", __func__);
		return -1;
	}

	event = atbm_kzalloc(sizeof(struct atbm_status_event), GFP_KERNEL);
	if(event == NULL){
		atbm_printk_err("%s: event atbm_kzalloc is null.\n", __func__);
		return -1;
	}

	if (event_buffer != NULL){
		memcpy(&(event->status.event_buffer), event_buffer, event_len);
	}
	event->status.type = type;
	event->status.driver_mode = driver_mode;

	spin_lock_bh(&s_status_queue_lock);
	first = list_empty(&s_status_head);
	list_add_tail(&event->link, &s_status_head);
	s_cur_status_list_cnt++;
	spin_unlock_bh(&s_status_queue_lock);
	
	if (1){
		return 1;//need async notify usr layer
	}
	else{
		return 0;//not need async notify usr layer
	}
}

void atbm_ioctl_ble_adv_rpt_async(u8 *event_buffer, u16 event_len)
{
	if (atbm_ioctl_notify_add(0, 0, event_buffer, event_len) > 0)
	{
		kill_fasync (&connect_async, SIGIO, POLL_IN);
	}
}

void atbm_ioctl_ble_conn_rpt_async(u8 *event_buffer, u16 event_len)
{
	if (atbm_ioctl_notify_add(1, 0, event_buffer, event_len) > 0)
	{
		kill_fasync (&connect_async, SIGIO, POLL_IN);
	}
}

int atbm_ioctl_ble_start(struct ieee80211_local* local,u8 *data)
{
#ifdef CONFIG_WIFI_BT_COMB
	printk("atbm_ioctl_ble_start\n");
	//ble full stack COMB
	ieee80211_ble_commb_start(local);
//	ieee80211_ble_commb_subscribe(local, atbm_ble_dev_rx);
	return 0;
#else
//ble adv/scan comb
	return atbm_ioctl_ble_adv_coexit_start(data);
#endif
	}
	
int atbm_ioctl_ble_stop(struct ieee80211_local* local, u8* data)
{
#ifdef CONFIG_WIFI_BT_COMB
	printk("atbm_ioctl_ble_stop\n");
//ble full stack COMB
	ieee80211_ble_commb_unsubscribe(local);
	ieee80211_ble_commb_stop(local);
	return 0;
#else
//ble adv/scan comb
	return atbm_ioctl_ble_adv_coexit_stop(data);
#endif
	}
	
int atbm_ble_dev_rx(u8* event_buffer, size_t event_len)
{
	//printk("atbm_ble_dev_rx len %d\n", event_len);
	//frame_hexdump_wp("rx:", event_buffer, event_len);
	if (atbm_ioctl_notify_add(0, 0, event_buffer, event_len) > 0) {
		kill_fasync(&connect_async, SIGIO, POLL_IN);
	}
	return 0;
	}
void atbm_ble_dev_tx(uint8_t* buf)
{
#ifdef CONFIG_WIFI_BT_COMB
	//struct ble_hci_hif_pkt* tx_pkt;
	struct atbm_common* hw_priv = atbm_info.hw_priv;
	struct ieee80211_local* local = hw_to_local(hw_priv->hw);
	//struct platform_device* pble_dev = &local->ble_dev;
	char* xmit_buff;
	uint8_t* tx_pkt = &buf[2];
	u16 tx_len = *(u16*)buf;
	xmit_buff = NULL;

	//printk("atbm_ble_dev_tx %d\n", tx_len);
	rcu_read_lock();

	xmit_buff = ieee80211_ble_commb_ble_alloc_xmit( HCI_ACL_SHARE_SIZE);

	if (xmit_buff == NULL) {
		goto pkt_free;
	}

	//printk("atbm_ble_dev_tx %p tx_pkt %p len %d\n", xmit_buff, tx_pkt, tx_len);
	memcpy(xmit_buff, tx_pkt, tx_len);
	ieee80211_ble_commb_xmit(local, xmit_buff, tx_len);

pkt_free:
	rcu_read_unlock();
	//ble_hci_trans_free_hif_pkt(tx_pkt);
	return;
#else
	printk("unsupport ble mode\n");
#endif //#ifdef CONFIG_WIFI_BT_COMB
}


static long atbm_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct atbm_common* hw_priv = atbm_info.hw_priv;
	struct ieee80211_local* local;
	if (atbm_info.hw_priv == NULL){
		atbm_printk_err("%s: atbm ioctl is not open.\n", __func__);
		return -1;
	}
	local = hw_to_local(hw_priv->hw);
	switch (cmd)
	{
		case ATBM_BLE_COEXIST_START:
			memset(atbm_ioctl_data, 0, sizeof(atbm_ioctl_data));
			if (0 != copy_from_user(atbm_ioctl_data, (struct at_cmd_direct *)arg, sizeof(atbm_ioctl_data)))
			{
				atbm_printk_err("%s: copy_from_user err.\n", __func__);
				ret = -1;
				break;
			}
			atbm_ioctl_ble_start(local,atbm_ioctl_data);
			break;
		case ATBM_BLE_COEXIST_STOP:
			memset(atbm_ioctl_data, 0, sizeof(atbm_ioctl_data));
			if (0 != copy_from_user(atbm_ioctl_data, (struct at_cmd_direct *)arg, sizeof(atbm_ioctl_data)))
			{
				atbm_printk_err("%s: copy_from_user err.\n", __func__);
				ret = -1;
				break;
			}
			atbm_ioctl_ble_stop(local,atbm_ioctl_data);
			break;
#ifdef CONFIG_ATBM_BLE_ADV_COEXIST
		case ATBM_BLE_SET_ADV_DATA:
			memset(atbm_ioctl_data, 0, sizeof(atbm_ioctl_data));
			if (0 != copy_from_user(atbm_ioctl_data, (struct at_cmd_direct *)arg, sizeof(atbm_ioctl_data)))
			{
				atbm_printk_err("%s: copy_from_user err.\n", __func__);
				ret = -1;
				break;
			}
			atbm_ioctl_ble_set_adv_data(atbm_ioctl_data);		
			break;

		case ATBM_BLE_ADV_RESP_MODE_START:
			memset(atbm_ioctl_data, 0, sizeof(atbm_ioctl_data));
			if (0 != copy_from_user(atbm_ioctl_data, (struct at_cmd_direct *)arg, sizeof(atbm_ioctl_data)))
			{
				atbm_printk_err("%s: copy_from_user err.\n", __func__);
				ret = -1;
				break;
			}
			atbm_ioctl_ble_adv_resp_start(atbm_ioctl_data);	
			break;
		case ATBM_BLE_SET_RESP_DATA:
			memset(atbm_ioctl_data, 0, sizeof(atbm_ioctl_data));
			if (0 != copy_from_user(atbm_ioctl_data, (struct at_cmd_direct *)arg, sizeof(atbm_ioctl_data)))
			{
				atbm_printk_err("%s: copy_from_user err.\n", __func__);
				ret = -1;
				break;
			}
			atbm_ioctl_ble_set_resp_data(atbm_ioctl_data);	
			break;
#endif  //#ifdef CONFIG_ATBM_BLE_ADV_COEXIST
		case ATBM_BLE_HIF_TXDATA:
			memset(atbm_ioctl_data, 0, sizeof(atbm_ioctl_data));
			if (0 != copy_from_user(atbm_ioctl_data, (struct at_cmd_direct*)arg, sizeof(atbm_ioctl_data))) {
				atbm_printk_err("%s: copy_from_user err.\n", __func__);
				ret = -1;
				break;
			}
			//frame_hexdump_wp("HIF_TXDATA ->", atbm_ioctl_data, 32);
			atbm_ble_dev_tx(atbm_ioctl_data);
			break;
		default:
			atbm_printk_err("%s cmd %d invalid.\n", __func__, cmd);
			ret = -1;
	}

	return ret;
}

static int atbm_ioctl_fasync(int fd, struct file *filp, int on)
{
	return fasync_helper(fd, filp, on, &connect_async);
}

static int atbm_ioctl_open(struct inode *inode, struct file *filp)
{
	int time_cnt = 100;
	struct atbm_common *hw_priv = NULL;

	while (NULL == (hw_priv=atbm_hw_priv_dereference()))
	{
		msleep(10);
		time_cnt--;
		if (time_cnt <= 0)
		{
			return -1;
		}
	}
	while (!hw_priv->init_done)
	{
		msleep(10);
		time_cnt--;
		if (time_cnt <= 0)
		{
			return -1;
		}
	}
	
	spin_lock_bh(&s_status_queue_lock);
	while (!list_empty(&s_status_head)) {
		struct atbm_status_event *event =
			list_first_entry(&s_status_head, struct atbm_status_event,
			link);
		list_del(&event->link);
		atbm_kfree(event);
		s_cur_status_list_cnt--;
	}
	spin_unlock_bh(&s_status_queue_lock);

	atbm_info.hw_priv = hw_priv;
	filp->private_data = &atbm_info;
	atbm_printk_debug("atbm_ioctl_open cost time: %d ms\n", 10*(100-time_cnt));
	return 0;
}

static int atbm_ioctl_release(struct inode *inode, struct file *filp)
{
	atbm_ioctl_fasync(-1, filp, 0);
	filp->private_data = NULL;
	return 0;
}

static ssize_t atbm_ioctl_read(struct file *filp, char __user *buff, size_t len, loff_t *off)
{
	int ret = 0;
	struct atbm_status_event *event = NULL;

	if (atbm_info.hw_priv == NULL){
		atbm_printk_err("%s: atbm ioctl is not open.\n", __func__);
		return -1;
	}

	if (sizeof(struct ioctl_status_async) > len)
	{
		atbm_printk_err("%s: buff len is not enough.\n", __func__);
		return -1;
	}

	if (list_empty(&s_status_head))
	{
		atbm_printk_err("%s: status list is empty.\n", __func__);
		return -1;
	}

	spin_lock_bh(&s_status_queue_lock);
	event = list_first_entry(&s_status_head, struct atbm_status_event, link);
	if (event)
	{
		if (s_cur_status_list_cnt >= 2)
		{
			event->status.list_empty = 0;
		}
		else
		{
			event->status.list_empty = 1;
		}
		spin_unlock_bh(&s_status_queue_lock);
		ret = copy_to_user(buff, &event->status, sizeof(struct ioctl_status_async));
		spin_lock_bh(&s_status_queue_lock);
		if (ret)
		{
			atbm_printk_err("%s: copy_to_user err %d.\n", __func__, ret);
		}
		else
		{
			list_del(&event->link);
			atbm_kfree(event);
			s_cur_status_list_cnt--;
		}
	}
	else
	{
		ret = -1;
	}
	spin_unlock_bh(&s_status_queue_lock);
	
	if (ret)
	{
		return -1;
	}

	return sizeof(struct ioctl_status_async);
}

static struct file_operations atbm_ioctl_fops = {
    .owner = THIS_MODULE,
    .open = atbm_ioctl_open,
    .release = atbm_ioctl_release,
    .read = atbm_ioctl_read,
    .unlocked_ioctl = atbm_unlocked_ioctl,
    .fasync = atbm_ioctl_fasync,
};

int atbm_ioctl_add(void)
{
	memset(&atbm_info, 0, sizeof(struct atbm_info));

	alloc_chrdev_region(&atbm_info.devid, 0, 1, "atbm_ioctl");

	atbm_info.my_cdev = cdev_alloc();
	cdev_init(atbm_info.my_cdev, &atbm_ioctl_fops);

	atbm_info.my_cdev->owner = THIS_MODULE;
	cdev_add(atbm_info.my_cdev, atbm_info.devid, 1);

	atbm_info.my_class = class_create(THIS_MODULE, "atbm_ioctl_class");
	atbm_info.my_device = device_create(atbm_info.my_class, NULL, atbm_info.devid, NULL, "atbm_ioctl");

	spin_lock_init(&s_status_queue_lock);
	INIT_LIST_HEAD(&s_status_head);

	atbm_printk_always("atbm_ioctl_add\n");
	return 0;
}

void atbm_ioctl_free(void)
{
	device_destroy(atbm_info.my_class, atbm_info.devid);
	class_destroy(atbm_info.my_class);
	cdev_del(atbm_info.my_cdev);
	unregister_chrdev_region(atbm_info.devid, 1);
	memset(&atbm_info, 0, sizeof(struct atbm_info));

	spin_lock_bh(&s_status_queue_lock);
	while (!list_empty(&s_status_head)) {
		struct atbm_status_event *event =
			list_first_entry(&s_status_head, struct atbm_status_event,
			link);
		list_del(&event->link);
		atbm_kfree(event);
		s_cur_status_list_cnt--;
	}
	spin_unlock_bh(&s_status_queue_lock);
}
#endif