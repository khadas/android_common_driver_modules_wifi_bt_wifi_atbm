/*
 * Copyright 2018-, altobeam.inc
 */

#include <net/atbm_mac80211.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/bitmap.h>
#ifdef CONFIG_ATBM_PM_QOS
#include <linux/pm_qos.h>
#endif
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <net/cfg80211.h>
#ifdef CONFIG_WIRELESS_EXT
#include <net/iw_handler.h>
#endif
#ifdef IPV6_FILTERING
#include <net/if_inet6.h>
#include <net/addrconf.h>
#endif /*IPV6_FILTERING*/

#include "ieee80211_i.h"
#include "driver-ops.h"
#include "rate.h"
#include "mesh.h"
#include "wep.h"
#include "led.h"
#include "cfg.h"
#include "debugfs.h"
#include "../sbus.h"
#include "atbm_common.h"
#include "../apollo.h"
#include "../smartconfig.h"
#include "../wsm.h"
#include "../internal_cmd.h"
#include "../sta.h"


#define ATBM_WEXT_PROCESS_PARAMS(_start_pos,_length,_val,_process,_err_code,_exit_lable,_status)		\
do{													\
	char const *pos_next = NULL;					\
	pos_next = memchr(_start_pos,ATBM_SPACE,_length);	\
	if(pos_next == NULL) pos_next = memchr(_start_pos,ATBM_TAIL,_length);	\
	if(_process(_start_pos,pos_next - _start_pos,&_val) == _err_code){	\
		atbm_printk_err("%s:line(%d) err\n",__func__,__LINE__);			\
		_status = -EINVAL;											\
		goto _exit_lable;												\
	}															\
	pos_next++;													\
	_length -= (pos_next-_start_pos);										\
	_start_pos = pos_next;												\
}while(0)


#define FREQ_CNT	(10)
#define DCXO_CODE_MINI		0//24//0
#define DCXO_CODE_MAX		127//38//63
#define TARGET_FREQOFFSET_HZ  (7000)

#define DCXO_TRIM_REG 0x1610100c //bit 5:0
#define CHIP_VERSION_REG 0x0acc017c //chip version reg address
#define HW_CHIP_VERSION_AthenaB (0x24)
#define HW_CHIP_VERSION_AresB (0x49)
#define N_BIT_TO_SIGNED_32BIT(v,n)	(s32)(((v) & BIT(n-1))?((v)|0xffffffff<<n):(v))

#define RX_STATUS_ADDR	(0x161001d8)

struct rxstatus{
	u32 GainImb;
	u32 PhaseImb;
	u32 Cfo;
	u32 evm;
	u32  RSSI;
	u32 probcnt;
};

u32 chipversion = 0;

u8 ETF_bStartTx = 0;
u8 ETF_bStartRx = 0;
//char ch_and_type[20] = {0};

u8 CodeStart = 0;
u8 CodeEnd = 0;



u8 ucWriteEfuseFlag = 0;

int Atbm_Test_Success = 0;
int atbm_test_rx_cnt = 0;
int txevm_total = 0;

struct efuse_headr efuse_data_etf;
struct rxstatus_signed gRxs_s;
struct etf_test_config etf_config;

#ifdef CONFIG_ATBM_BLE
extern int fw_use_ble;
#endif
extern int DCXOCodeWrite(struct atbm_common *hw_priv,u8 data);
extern u8 DCXOCodeRead(struct atbm_common *hw_priv);
extern int atbm_direct_read_reg_32(struct atbm_common *hw_priv, u32 addr, u32 *val);
extern int atbm_direct_write_reg_32(struct atbm_common *hw_priv, u32 addr, u32 val);

extern int wsm_start_tx(struct atbm_common *hw_priv, struct ieee80211_vif *vif);
extern int wsm_stop_tx(struct atbm_common *hw_priv);
extern int wsm_start_tx_v2(struct atbm_common *hw_priv, struct ieee80211_vif *vif );
extern int MacStringToHex(char *mac, u8  *umac);
extern u32 MyRand(void);
#ifdef CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
extern int wsm_send_result(struct atbm_common *hw_priv, struct ieee80211_vif *vif );
#endif
extern u32 GetChipCrystalType(struct atbm_common *hw_priv);

#ifdef CONFIG_WIRELESS_EXT

#define RATE_CONTROL_UNICAST 1

#define	arraysize(a)	sizeof(a)/sizeof(a[0])

static int atbm_ioctl_stop_rx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_stop_tx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);

extern void atbm_set_freq(struct ieee80211_local *local);
extern void atbm_set_tx_power(struct atbm_common *hw_priv, int txpw);
extern int str2mac(char *dst_mac, char *src_str);
extern int atbm_tool_rts_threshold;
extern int atbm_tool_shortGi;
extern int atbm_tesmode_reply(struct wiphy *wiphy,const void *data, int len);
extern void atbm_set_shortGI(u32 shortgi);
extern int wsm_start_tx(struct atbm_common *hw_priv, struct ieee80211_vif *vif);
extern int wsm_stop_tx(struct atbm_common *hw_priv);
static int atbm_ioctl_stop_tx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_stop_rx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
int atbm_ioctl_etf_result_get(struct net_device *dev, struct iw_request_info *info, union iwreq_data  *wrqu, char *extra);
extern int wsm_get_efuse_status(struct atbm_common *hw_priv, struct ieee80211_vif *vif );
u32 GetChipVersion(struct atbm_common *hw_priv);
u32 MyRand(void);
//static void etf_PT_test_config(char *param);
extern int etf_v2_scan_end(struct atbm_common *hw_priv, struct ieee80211_vif *vif );
extern void etf_v2_scan_rx(struct atbm_common *hw_priv,struct sk_buff *skb,u8 rssi );

#ifdef CONFIG_ATBM_IWPRIV_USELESS
static int Test_FreqOffset(struct atbm_common *hw_priv, u32 *dcxo, int *pfreqErrorHz, struct rxstatus_signed *rxs_s, int channel);
#endif
/*
static const u32 band_table[21] = {10, 20, 55, 110, 60, 90, 120,
								180, 240, 360, 480, 540, 65, 130,
								195, 260, 390, 520, 585, 650, 320};

*/

struct iw_handler_def atbm_handlers_def;
static const struct iw_priv_args atbm_privtab[] = {
#ifdef CONFIG_ATBM_PRIV_HELP
		{SIOCIWFIRSTPRIV + 0x0, IW_PRIV_TYPE_CHAR | 17, 0, "help"},
#endif
#ifdef ATBM_SUPPORT_SMARTCONFIG
		{SIOCIWFIRSTPRIV + 0x1, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 1, 0, "smartcfg_start"},	
#endif
		{SIOCIWFIRSTPRIV + 0x2, IW_PRIV_TYPE_CHAR | 1000, 0, "start_tx"},
		{SIOCIWFIRSTPRIV + 0x3, IW_PRIV_TYPE_CHAR | 513, 0, "stop_tx"},
		{SIOCIWFIRSTPRIV + 0x4, IW_PRIV_TYPE_CHAR | 50, 0, "start_rx"},
		{SIOCIWFIRSTPRIV + 0x5, 0, IW_PRIV_TYPE_CHAR|513, "stop_rx"},
		{SIOCIWFIRSTPRIV + 0x6, IW_PRIV_TYPE_CHAR | 5, 0, "fwdbg"},
		{SIOCIWFIRSTPRIV + 0x7, 0, IW_PRIV_TYPE_CHAR|513, "rx_statis"},
		{SIOCIWFIRSTPRIV + 0x8, IW_PRIV_TYPE_CHAR | 50, 0, "fwcmd"},
#ifdef ATBM_SUPPORT_SMARTCONFIG
		{SIOCIWFIRSTPRIV + 0xa, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 1, 0, "smartcfg_stop"},
#endif
		{SIOCIWFIRSTPRIV + 0xb, IW_PRIV_TYPE_CHAR | 500,IW_PRIV_TYPE_CHAR|513, "common"},
		{SIOCIWFIRSTPRIV + 0xc, IW_PRIV_TYPE_CHAR | 10, 0, "set_gi"},
		{SIOCIWFIRSTPRIV + 0xd, IW_PRIV_TYPE_CHAR | 10, 0, "getmac"},
#ifdef CONFIG_ATBM_START_WOL_TEST
		{SIOCIWFIRSTPRIV + 0xe, IW_PRIV_TYPE_CHAR | 10, 0, "wolEn"},
#endif
#ifdef CONFIG_ATBM_IWPRIV_USELESS
		{SIOCIWFIRSTPRIV + 0xf, IW_PRIV_TYPE_CHAR | 16, 0, "get_rx_stats"},
#endif
		{SIOCIWFIRSTPRIV + 0x10, IW_PRIV_TYPE_CHAR | 10, 0, "rts_threshold"},
#ifdef ATBM_SUPPORT_SMARTCONFIG
		{SIOCIWFIRSTPRIV + 0x11, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 1, 0, "smartonv2"},
#endif
		{SIOCIWFIRSTPRIV + 0x12, IW_PRIV_TYPE_CHAR | 16, 0, "etf_result_get"},
#ifdef ATBM_SUPPORT_SMARTCONFIG
		{SIOCIWFIRSTPRIV + 0x13, IW_PRIV_TYPE_CHAR | IW_PRIV_SIZE_FIXED | 1, 0, "smartoffv2"},
#endif
#ifdef ATBM_PRIVATE_IE
		/*Private IE for Scan*/
		{SIOCIWFIRSTPRIV + 0x14, IW_PRIV_TYPE_CHAR | 500, 0, "insert_data"},
		{SIOCIWFIRSTPRIV + 0x15, IW_PRIV_TYPE_CHAR | 500, 0, "get_data"},
		{SIOCIWFIRSTPRIV + 0x16, IW_PRIV_TYPE_CHAR | 500, 0, "send_msg"},
		{SIOCIWFIRSTPRIV + 0x17, IW_PRIV_TYPE_CHAR | 500, 0, "recv_msg"},
#ifdef USE_HIDDEN_SSID
		{SIOCIWFIRSTPRIV + 0x19, IW_PRIV_TYPE_CHAR | 32, 0, "hide_ssid"},
#else
	//	{SIOCIWFIRSTPRIV + 0x19, IW_PRIV_TYPE_CHAR | 32, 0, "get_state"},
#endif
		{SIOCIWFIRSTPRIV + 0x1A, IW_PRIV_TYPE_CHAR | 32, 0, "set_freq"},
		{SIOCIWFIRSTPRIV + 0x1B, IW_PRIV_TYPE_CHAR | 500, 0, "best_ch_scan"},
		
		{SIOCIWFIRSTPRIV + 0x1D, IW_PRIV_TYPE_CHAR | 32, 0, "get_tp_rate"},
		{SIOCIWFIRSTPRIV + 0x1E, IW_PRIV_TYPE_CHAR | 32, 0, "set_txpower"},
#ifdef CONFIG_ATBM_STA_LISTEN
		{SIOCIWFIRSTPRIV + 0x1F, IW_PRIV_TYPE_CHAR | 32, 0, "sta_channel"},
#endif

#else
#ifdef USE_HIDDEN_SSID
		{SIOCIWFIRSTPRIV + 0x14, IW_PRIV_TYPE_CHAR | 32, 0, "hide_ssid"},
#else
	//	{SIOCIWFIRSTPRIV + 0x14, IW_PRIV_TYPE_CHAR | 32, 0, "get_state"},
#endif
		{SIOCIWFIRSTPRIV + 0x15, IW_PRIV_TYPE_CHAR | 500, 0, "best_ch_scan"},
		
		{SIOCIWFIRSTPRIV + 0x16, IW_PRIV_TYPE_CHAR | 32, 0, "set_txpower"},
		{SIOCIWFIRSTPRIV + 0x17, IW_PRIV_TYPE_CHAR | 32, 0, "get_tp_rate"},
		{SIOCIWFIRSTPRIV + 0x18, IW_PRIV_TYPE_CHAR | 32, 0, "set_freq"},
#ifdef CONFIG_ATBM_STA_LISTEN
		{SIOCIWFIRSTPRIV + 0x19, IW_PRIV_TYPE_CHAR | 32, 0, "sta_channel"},
#endif
#endif	
};
#ifdef CONFIG_ATBM_PRIV_HELP
static int atbm_ioctl_command_help(struct net_device * dev,struct iw_request_info * ifno,union iwreq_data * wrqu,char * ext)
{
	int ret = 0;
		atbm_printk_wext("usage: 		iwpriv wlan0 <cmd> [para]..,\n");
		atbm_printk_wext("fwdbg		<0|1> = gets/sets firmware debug message switch, when setting, 0, close, 1, open\n");
		atbm_printk_wext("fwcmd		<firmware cmd line> = letting firmware performance command,e.g:fwcmd para1,para2,parq3....\n");
		atbm_printk_wext("start_tx 	<channel,rate,len,is_40M,greedfiled> = start transmmit \n");
		atbm_printk_wext("		channel value:1~14 \n");
		atbm_printk_wext("		rate id: 1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54, 6.5, 13, 19.5,26, 39, 52, 58.5, 65, 32\n");
		atbm_printk_wext("		len range:100~1024\n");
		atbm_printk_wext("		is_40M value: 1:40M,0:20M\n");
		atbm_printk_wext("		greedfiled value: 1:greedfiled,0:\n");
		atbm_printk_wext("stop_tx		NO prarameter = stop transmmit\n");
		atbm_printk_wext("start_rx 	<[1~14],[0|1]> = start receive,parameter:channel,channel type;1:40M,0:20M\n");
		atbm_printk_wext("stop_rx		NO parameter = stop receive\n");
		atbm_printk_wext("set_gi		<0|1> = 1,support shortGI; 0, not support shortGI\n");
		atbm_printk_wext("rts_threshold		<show|value> = show or set rts threshold\n");
		atbm_printk_wext("rate		<show|free|rate id> = show rate,or free a fixed rate,or forces a fixed rate support");
		atbm_printk_wext(" rate id: 1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54, 6.5, 13, 19.5,26, 39, 52, 58.5, 65\n");
		atbm_printk_wext("getmac		NO Parameter = get mac address\n");
		atbm_printk_wext("wolEn		<0|1> = 1,enable wol; 0, disable wol\n");
		atbm_printk_wext("get_rx_stats	<1>\n");
		atbm_printk_wext("freqoffset		<0|1> 0:not write efuse; 1: write efuse \n");
		atbm_printk_wext("etf_result_get  get the test result \n");
#ifdef ATBM_PRIVATE_IE
		atbm_printk_wext("insert_data      insert private user data to (Probe Req or Beacon or Probe Resp) \n");
		atbm_printk_wext("get_data         obtain private user data from the broadcast packet \n");
		atbm_printk_wext("send_msg         start private scan according to the channel setting \n");
		atbm_printk_wext("recv_msg         recv broadcast device information of contain private IE \n");
		atbm_printk_wext("ipc_reset        reset ipc private scan function \n");
		atbm_printk_wext("channel_switch   switch channle to another \n");
#endif
//		atbm_printk_wext("hide_ssid        Enable or Disble hidden ssid func, only for AP mode \n");
		atbm_printk_wext("set_freq		 param1: channel [1:14],param2: freq val(2380 or 2504) \n");
		atbm_printk_wext("set_txpower         1: high tx power, 0: normal tx power \n");
		atbm_printk_wext("get_tp_rate         obtain current throughput, AP mode need to add mac address of station \n");
		atbm_printk_wext("best_ch_start         start the best channel scan \n");
		atbm_printk_wext("best_ch_end		   end the best channel scan \n");
		atbm_printk_wext("best_ch_rslt		   get the best channel scan result \n");
#ifdef SSTAR_FUNCTION
		atbm_printk_wext("getSigmstarEfuse		   get sigmstar 256bits efuse \n");
		atbm_printk_wext("setSigmstarEfuse		   set sigmstar 256bits efuse \n");
#endif
		
		atbm_printk_wext("common help 	get lager infomation\n");
	return ret;
}
#endif

typedef struct iwripv_common_cmd{
	const char *cmd;
	const char cmd_len;
	int (*handler)(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
	const char *uage;
}iwripv_common_cmd_t;


static int atbm_ioctl_common_help(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_rssi(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#ifdef SSTAR_FUNCTION

static int atbm_ioctl_get_SIGMSTAR_256BITSEFUSE(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_set_SIGMSTAR_256BITSEFUSE(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
#endif
static int atbm_ioctl_get_channel_idle(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_set_efuse(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_get_efuse_first(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_get_efuse(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_get_efuse_free_space(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_get_efuse_all_data(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);



#ifdef CONFIG_ATBM_IWPRIV_USELESS
static int atbm_ioctl_freqoffset(struct net_device *dev, struct iw_request_info *info, union iwreq_data  *wrqu, char *extra);
static int atbm_ioctl_channel_test_start(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);

#endif/*CONFIG_ATBM_IWPRIV_USELESS*/
static int atbm_ioctl_send_singleTone(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_set_duty_ratio(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);

#ifdef CONFIG_ATBM_SUPPORT_AP_CONFIG
static int atbm_ioctl_set_ap_conf(struct net_device *dev, struct iw_request_info *info,union iwreq_data *wrqu, char *ext);
#endif/*CONFIG_ATBM_SUPPORT_AP_CONFIG*/

#ifdef CONFIG_ATBM_MONITOR_SPECIAL_MAC
static int atbm_ioctl_rx_monitor_mac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_rx_monitor_mac_status(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif/*CONFIG_ATBM_MONITOR_SPECIAL_MAC*/

#ifdef CONFIG_IEEE80211_SPECIAL_FILTER
static int atbm_ioctl_rx_filter_frame(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_rx_filter_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_rx_filter_clear(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_rx_filter_show(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif/*CONFIG_IEEE80211_SPECIAL_FILTER*/
#ifdef HIDDEN_SSID
extern int atbm_upload_beacon_private(struct atbm_vif *priv);
static int atbm_ioctl_set_hidden_ssid(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif/*HIDDEN_SSID*/

static int atbm_ioctl_get_Last_mac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_First_mac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_Tjroom(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_set_calibrate_flag(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_set_all_efuse(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_set_all_efuse_V2(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_associate_sta_status(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#ifdef ATBM_PRIVATE_IE
static int atbm_ioctl_ie_ipc_clear_insert_data(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_ie_insert_vendor_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
#endif/*ATBM_PRIVATE_IE*/
static int atbm_set_power_save_mode(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_gpio_config(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_gpio_output(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_edca_params(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_edca_params(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_txposer_status(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);

extern void atbm_get_delta_gain(char *srcData,int *allgain,int *bgain,int *gngain);
static int atbm_ioctl_set_txpwr_by_file(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_set_rate_txpwr_by_file(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_set_management_frame_rate(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_work_channel(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_set_country_code(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);
static int atbm_ioctl_get_country_code(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext);


static int atbm_ioctl_get_cur_max_rate(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_cfg_txpower_by_file(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
int atbm_ioctl_get_gpio4(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
int atbm_ioctl_get_cfo_cali_data(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
int atbm_ioctl_send_vendor_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
int atbm_ioctl_get_vendor_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
int atbm_ioctl_set_listen_probe_req(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_send_probe_resp(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_stop_send_probe_resp(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#ifdef CONFIG_ATBM_AP_CHANNEL_CHANGE_EVENT
int atbm_ioctl_change_ap_channel(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif
#ifdef DEBUG_CHANNEL_PARAM

static int atbm_ioctl_get_cca_threshold(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_rts_threshold(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_rts_duration(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_get_noise_level(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);

static int atbm_ioctl_get_snr(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#ifdef CONFIG_JUAN_MISC

static int atbm_ioctl_common_get_tim(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_common_set_tim(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif
#endif

#ifdef CONFIG_ATBM_BLE_ADV_COEXIST
static int atbm_ioctl_ble_coexist_cmd(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
static int atbm_ioctl_ble_set_adv_data_cmd(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif

#ifdef CONFIG_ATBM_SUPPORT_REKEY
static int atbm_ioctl_set_rekey(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif
static int atbm_ioctl_get_wifi_state(struct net_device *dev, struct iw_request_info *info,  union iwreq_data  *wrqu, char *extra);


extern int atbm_wifi_bt_comb_get(void);
extern void atbm_wifi_bt_comb_set(int status);
static int atbm_ioctl_fw_reset(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int i,strheadLen = 0;
	char *buff_data =NULL;
	int ps_elems = 0;

	buff_data = atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);

	if(buff_data == NULL){
		atbm_printk_wext("%s atbm_kzalloc error!\n",__func__);
		return  -EINVAL;
	}
	
	if(copy_from_user(buff_data, wrqu->data.pointer, wrqu->data.length)){
		atbm_printk_wext("%s copy_from_user error!\n",__func__);
		atbm_kfree(buff_data);
		return -EINVAL;
	}
	buff_data[wrqu->data.length] = 0;
	for(i=0;i<wrqu->data.length;i++)
	{
		if(buff_data[i] == ',')
		{
			strheadLen=i+1;
			break;
		}
	}
	
	
	ps_elems = buff_data[strheadLen];

	if (ps_elems == 0x31)
		atbm_wifi_bt_comb_set(1);
	else
		atbm_wifi_bt_comb_set(0);

	
//	atbm_wifi_bt_comb_set(hw_priv->wifi_ble_comb);
	atbm_printk_err("\n======>>> reload %s firmware <<<======\n\n",atbm_wifi_bt_comb_get()?"WIFI BLE COMB":"only WIFI");
	atbm_kfree(buff_data);
	
	atbm_bh_halt(hw_priv);

	return 0;
}


iwripv_common_cmd_t common_cmd[]={
	{"help",4,atbm_ioctl_common_help,"get help information"},
	{"get_rssi",8,atbm_ioctl_get_rssi,"iwpriv wlan0 common get_rssi [mac]"},
	{"stations_show",13,atbm_ioctl_associate_sta_status,"get sta mode support rate"},

#ifdef CONFIG_ATBM_IWPRIV_USELESS
	{"channel_test_start",18,atbm_ioctl_channel_test_start,"channel_test_start"},
#endif
	{"get_channel_idle",16,atbm_ioctl_get_channel_idle,"get channel idle value,lager be better"},
	{"setEfuse_dcxo",13,atbm_ioctl_set_efuse,"effect freq offsert"},
	{"setEfuse_deltagain",18,atbm_ioctl_set_efuse,"effect tx power"},
#ifdef CONFIG_ATBM_IWPRIV_USELESS
	{"setEfuse_tjroom",18,atbm_ioctl_set_efuse,"not allow change"},
#endif
	{"get_tjroom",10,atbm_ioctl_get_Tjroom,"get efuse tjroom"},
	{"setEfuse_mac",12,atbm_ioctl_set_efuse,"change mac addr,The reload driver takes effect "},
	{"getEfuse",8,atbm_ioctl_get_efuse,"get efsue value"},
	{"getefusefirst",13,atbm_ioctl_get_efuse_first,"get first set efuse,Query whether changes have been made"},
	{"EfusefreeSpace",14,atbm_ioctl_get_efuse_free_space,"Gets the size of Efuse remaining space"},
	{"getallEfuse",11,atbm_ioctl_get_efuse_all_data,"Gets all efuse data"},
#ifdef CONFIG_ATBM_IWPRIV_USELESS

	{"freqoffset",10,atbm_ioctl_freqoffset,"i don't know function"},
#endif
	{"singletone",10,atbm_ioctl_send_singleTone,"Transmit single carrier"},
	{"duty_ratio",10,atbm_ioctl_set_duty_ratio,"Modify the offer duty ratio in the ETF mode,only change 11n"},
#ifdef CONFIG_ATBM_SUPPORT_AP_CONFIG
	{"ap_conf",7,atbm_ioctl_set_ap_conf,"Fixed a channel scanning"},
#endif
#ifdef CONFIG_ATBM_MONITOR_SPECIAL_MAC
	{"monitor_mac",11,atbm_ioctl_rx_monitor_mac,"Add a MAC address to the hardware to be filtered"},
	{"stations_show",14,atbm_ioctl_rx_monitor_mac_status,"Is there a packet with the newly set MAC address for use with [monitor_mac]"},
#endif
#ifdef CONFIG_IEEE80211_SPECIAL_FILTER
	{"filter_frame",12,atbm_ioctl_rx_filter_frame,"Whitelist frame filtering,such as:beacon/probe"},
	{"filter_ie",9,atbm_ioctl_rx_filter_ie,"Whitelist frames filter certain IE fields"},
	{"filter_clear",12,atbm_ioctl_rx_filter_clear,"clear configuration with Whitelist frame filtering"},
	{"filter_show",11,atbm_ioctl_rx_filter_show,"show all configuration with Whitelist frame filtering"},
#endif
#ifdef HIDDEN_SSID
	{"ap_hide_ssid",12,atbm_ioctl_set_hidden_ssid,"set ap mode hidden ssid"},
#endif
	{"get_last_mac",12,atbm_ioctl_get_Last_mac,"get last set to efuse mac value"},
	{"get_first_mac",13,atbm_ioctl_get_First_mac,"get first set to efuse mac value"},
	
	{"set_cali_flag",13,atbm_ioctl_set_calibrate_flag,"The configuration items needed for the whole machine production and test"},
	{"set_all_efuse",13,atbm_ioctl_set_all_efuse,"set all efuse,including:dcxo ,deltagain,macaddr"},
	{"set_whole_efuse",13,atbm_ioctl_set_all_efuse_V2,"set all efuse,including:dcxo,deltagain,tjroom,macaddr"},
#ifdef ATBM_PRIVATE_IE
	{"ipc_reset",9,atbm_ioctl_ie_ipc_clear_insert_data,"clear ipc private ie"},
	{"vendor_ie",9,atbm_ioctl_ie_insert_vendor_ie,"insert vendor IE to (Probe Req)"},
#endif	
#ifdef SSTAR_FUNCTION
		{"getSigmstarEfuse",16,atbm_ioctl_get_SIGMSTAR_256BITSEFUSE,"get private efuse space value"},
		{"setSigmstarEfuse",16,atbm_ioctl_set_SIGMSTAR_256BITSEFUSE,"set private efuse space value"},
#endif

	{"power_save",10,atbm_set_power_save_mode,"0:normal mode 1:power save mode"},
	{"gpio_conf",9,atbm_ioctl_gpio_config,"Configure the GPIO state"},
	{"gpio_out",8,atbm_ioctl_gpio_output,"Set the GPIO output level"},
	{"edca_params",11,atbm_ioctl_edca_params,"set edca parameters"},
	{"get_edca_params",15,atbm_ioctl_get_edca_params,"get edca parameters"},
	{"txpower_status",14,atbm_ioctl_get_txposer_status,"get current txpower"},
#ifdef CONFIG_TXPOWER_DCXO_VALUE
	{"settxpower_byfile",17,atbm_ioctl_set_txpwr_by_file,"read "CONFIG_TXPOWER_DCXO_VALUE" to set efuse gain or dcxo"},
#else
	{"settxpower_byfile",17,atbm_ioctl_set_txpwr_by_file,"read /tmp/atbm_txpwer_dcxo_cfg.txt to set efuse gain or dcxo"},
#endif
#ifdef CONFIG_RATE_TXPOWER
	{"set_rate_power",14,atbm_ioctl_set_rate_txpwr_by_file,"read "CONFIG_RATE_TXPOWER" to set Power at different rates"},
#else
	{"set_rate_power",14,atbm_ioctl_set_rate_txpwr_by_file,"read /tmp/set_rate_power.txt to set Power at different rates"},
#endif
	{"get_cfg_txpower",15,atbm_ioctl_get_cfg_txpower_by_file,"read configured tx power by /tmp/atbm_txpwer_dcxo_cfg.txt and /tmp/set_rate_power.txt"},
	{"set_frame_rate",14,atbm_ioctl_set_management_frame_rate,"set manager frame rate 1Mbps"},
	{"get_maxrate",11,atbm_ioctl_get_cur_max_rate,"Gets the current primary shipping rate"},
	{"get_work_channel",16,atbm_ioctl_get_work_channel,"get current work channel"},
	{"country_code",12,atbm_ioctl_set_country_code,"country_code US/CN/JP ===> channel 11/13/14"},
	{"get_country_code",16,atbm_ioctl_get_country_code,"get country_code"},
#ifdef CONFIG_ATBM_GET_GPIO4
	{"get_gpio4",9,atbm_ioctl_get_gpio4,"get gpio4 value"},
#endif
	{"get_cali_data",9,atbm_ioctl_get_cfo_cali_data,"get dcxo & cfo calibration value"},
//	{"send_deauth",11,atbm_ioctl_send_deauth,"send brodcast deauth frame"},
	{"user_vendor_ie",14,atbm_ioctl_send_vendor_ie,"send special ie===>user_vendor_ie,ssid,psk"},
	{"get_user_vendor_ie",18,atbm_ioctl_get_vendor_ie,"get 6441 special data"},
	{"listen_probe_req",16,atbm_ioctl_set_listen_probe_req,"sta mode set listen probe req===>listen_probe_req,channel [channel,0~14]"},
#ifdef CONFIG_ATBM_AP_CHANNEL_CHANGE_EVENT

	{"change_chan",11,atbm_ioctl_change_ap_channel,"change_chan,chan,ht40,change ap channel,Must be provided by ATBM HOSTAPD��other version hostapd not support!"},
#endif
	{"send_probe_resp",15,atbm_ioctl_send_probe_resp,"until send probe resp,===>>send_probe_resp,ssid,psk"},
	{"stop_probe_resp",15,atbm_ioctl_stop_send_probe_resp,"stop send probe resp"},
#ifdef DEBUG_CHANNEL_PARAM
	{"get_cca_threshold",17,atbm_ioctl_get_cca_threshold,"get cca threshold"},
	{"get_rts_threshold",17,atbm_ioctl_get_rts_threshold,"get rts send packet lenth threshold"},
	{"get_rts_duration",16,atbm_ioctl_get_rts_duration,"get rts duration value"},
	{"get_noise_level",15,atbm_ioctl_get_noise_level,"To obtain the bottom noise, inig=60 is accurate"},
	{"get_snr",7,atbm_ioctl_get_snr,"The channel ratio is obtained, and the obtained value needs to be calculated by the formulaListed as follows:10*log10(4096/snr_val)"},
	
#ifdef CONFIG_JUAN_MISC	
	{"get_tim",7,atbm_ioctl_common_get_tim,"get beacon tim "},
	{"set_tim",7,atbm_ioctl_common_set_tim,"set beacon tim,eg:set_tim,ena,hex_val,"},
#endif
#endif
	{"fw_reset",8,atbm_ioctl_fw_reset,"fw reset"},
#ifdef CONFIG_ATBM_BLE_ADV_COEXIST
	{"ble_coexist",11,atbm_ioctl_ble_coexist_cmd,"ble coexist mode start/stop(0/1)"},
	{"ble_set_adv",11,atbm_ioctl_ble_set_adv_data_cmd,"ble set adv mac and data"},
#endif
#ifdef CONFIG_ATBM_SUPPORT_REKEY
	{"set_rekey",9,atbm_ioctl_set_rekey,"set_rekey data enable"},
#endif
	{"get_conn_state",14,atbm_ioctl_get_wifi_state,"sta mode get  connect state"},

	{NULL,0,NULL,NULL}
};

/**************************************************************************
**
** NAME        CmdLine_GetToken
**
** PARAMETERS:    *pLine -    current line location to parse.
**
** RETURNS:        the token located. It never be NULL, but can be "\0"
**              *pLine - next line location to parse.
**
** DESCRIPTION    Locate the next token from a cli.
**
**************************************************************************/
char * CmdLine_GetToken(char ** pLine)
{
    char *    str;
    char *    line;
    char ch;

    line = *pLine;

    /* escape white space */
    ch = line[0];
    while(ch != 0)
    {
        /* CmdLine_GetLine() has already replaced '\n' '\r' with 0 */
        if ( (ch == ' ') || (ch == ',') || (ch == '\t') ||(ch == ':'))
        {
            line++;
            ch = line[0];
            continue;
        }
        break;
    }

    str = line;
    while(ch != 0)
    {
        if ( (ch == ' ') || (ch == ',') || (ch == '\t')||(ch == ':') )
        {
            line[0] = 0;
            /* CmdLine_GetLine() has replaced '\n' '\r' with 0, so we can do line++ */
            line++;
            break;
        }
        line++;
        ch = line[0];
    }

    *pLine = line;

    return str;
}
int CmdLine_GetHex(char **pLine, unsigned int  *pDword)
{
    char *  str;
    char *  str0;
    int     got_hex;
    unsigned int  d = 0;

    str = CmdLine_GetToken(pLine);
    if (str[0] == 0)
    {
        return 0;
    }

    str0 = str;
    got_hex = 0;
    for (;;)
    {
        char    ch;

        ch = str[0];
        if (ch == 0)
        {
            break;
        }
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
        else
        {
            got_hex = 0;
            break;
        }
        got_hex = 1;
        str++;
    }
    if (got_hex)
    {
        *pDword = d;
    }
    else
    {
        atbm_printk_wext("Invalid hexdecimal: %s\n", str0);
    }

    return got_hex;
}
int CmdLine_GetSignInteger(char **pLine, int *pDword)
{
    char *  str;
    char *  str0;
    int     got_int;
	int negativeFlag = 0;
    int  d = 0;

    str = CmdLine_GetToken(pLine);
    if (str[0] == 0)
    {
        return 0;
    }

    str0 = str;
    got_int = 0;
    for (;;)
    {
        char    ch;

        ch = str[0];
        if (ch == 0)
        {
            break;
        }
		if((ch == '-') && (str0 == str))
		{
			negativeFlag = -1;
            str++;
		}else if (ch >= '0' && ch <= '9')
        {
            d = d*10 + (ch - '0');
            got_int = 1;
            str++;
        }
        else
        {
            got_int = 0;
            break;
        }
    }
    if (got_int)
    {
    	if (negativeFlag < 0)
        	*pDword = d * negativeFlag;
    	else
    		*pDword = d;	
    }
    else
    {
        atbm_printk_err("Invalid unsigned decimal: %s\n", str0);
    }

    return got_int;
}


/**************************************************************************
**
** NAME        CmdLine_GetInteger
**
** PARAMETERS:  *pLine - the current line location to parse.
**
** RETURNS:        TRUE if the next token is an unsigned decimal integer.
**              *pDword - the integer returned. Unchanged if return FALSE.
**              *pLine - next line location to parse.
**
** DESCRIPTION    Read an unsigned decimal integer from a cli.
**
**************************************************************************/
int CmdLine_GetInteger(char **pLine, unsigned int *pDword)
{
    char *  str;
    char *  str0;
    int     got_int;
    unsigned int  d = 0;

    str = CmdLine_GetToken(pLine);
    if (str[0] == 0)
    {
        return -1;
    }

    str0 = str;
    got_int = 0;
    for (;;)
    {
        char    ch;

        ch = str[0];
        if (ch == 0)
        {
            break;
        }
        if (ch >= '0' && ch <= '9')
        {
            d = d*10 + (ch - '0');
            got_int = 1;
            str++;
        }
        else
        {
            got_int = 0;
            break;
        }
    }
    if (got_int)
    {
        *pDword = d;
    }
    else
    {
        atbm_printk_wext("Invalid unsigned decimal: %s\n", str0);
    }

    return got_int;
}

static int atbm_ioctl_common_help(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	iwripv_common_cmd_t *cmd = common_cmd;
	atbm_printk_err("Usage: iwpriv [ifname] common [option] ?-?-\n");
	atbm_printk_err("	option			information");
	while(cmd->cmd){
		atbm_printk_err("	%-20s		%-s\n", cmd->cmd, cmd->uage);
		cmd++;
	}
	return 0;
}

#ifdef ATBM_SUPPORT_SMARTCONFIG
static int atbm_ioctl_smartconfig_start(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	u32 value;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	
	value = *extra - 0x30;
	
	atbm_smartconfig_start(hw_priv,value);

	return 0;
}


static int atbm_ioctl_smartconfig_stop(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	//u32 value;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;

	//value = *extra - 0x30;
	atbm_smartconfig_stop(hw_priv);
	return 0;
}

static int atbm_ioctl_smartconfig_start_v2(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	//u32 value;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	int i = 0;	
	u32 enable = 1;
	
	//value = *extra - 0x30;
	atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_SMARTCONFIG_START,
						&enable, sizeof(enable), vif->if_id));
					break;
				}
			}
	atbm_smartconfig_start(hw_priv,enable);
	return 0;
}

static int atbm_ioctl_smartconfig_stop_v2(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	//u32 value;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	int i = 0;	
	u32 enable = 0;

	//value = *extra - 0x30;
	atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_SMARTCONFIG_START,
						&enable, sizeof(enable), vif->if_id));
					break;
				}
			}
	atbm_smartconfig_start(hw_priv,enable);
	return 0;
}
#endif

static int atbm_ioctl_fwdbg(struct net_device *dev, struct iw_request_info *ifno, union iwreq_data *wrqu, char *ext)
{
	int i = 0;	
	int ret = 0;
	u8 ucDbgPrintOpenFlag = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	
	ucDbgPrintOpenFlag = *ext - 0x30;
	atbm_printk_wext("ALTM_GET_DBG_PRINT_TO_HOST\n");
	atbm_printk_wext("%s dbgflag:%d\n", __func__, ucDbgPrintOpenFlag);
			atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
					break;
				}
			}


	return ret;
}
extern void atbm_wifi_cfo_set(int status);
extern void atbm_wifi_adative_set(int status);

int fwcmd_common_deal(struct ieee80211_sub_if_data *sdata,char *extra,int len)
{

	if((len > 12) && (!memcmp(extra,"set_adaptive",12))){
		if(extra[13] == '1'){
			sdata->local->adaptive_started = true;
			sdata->local->adaptive_started_time = jiffies;
			atbm_printk_err("adaptive_started!\n");
			atbm_wifi_adative_set(1);
		}else if(extra[13] == '0')	{
			sdata->local->adaptive_started = false;
			atbm_printk_err("adaptive_stoped!\n");
			atbm_wifi_adative_set(0);
		}	
	}else if((len > 3) && (!memcmp(extra,"cfo",3))){
		if(extra[4] == '0'){
			atbm_wifi_cfo_set(0);
		}else{
			extra[4] = '1';
			atbm_wifi_cfo_set(1);
		}
	}
	return 0;
}

static int atbm_ioctl_fwcmd(struct net_device *dev, struct iw_request_info *ifno, union iwreq_data *wrqu, char *ext)
{
	
	int i = 0;
	int ret = 0;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	if(!(extra = atbm_kmalloc(wrqu->data.length+1,GFP_KERNEL)))
		return -ENOMEM;
	if(copy_from_user(extra, wrqu->data.pointer, wrqu->data.length)){
		atbm_kfree(extra);
		return -EINVAL;
	}

	if(wrqu->data.length <= 1){
		atbm_printk_err("invalid parameter!\n");
		atbm_printk_err("e.g:./iwpriv wlan0 fwcmd intr\n");
		atbm_kfree(extra);
		return -EINVAL;
	}

	for(i=0;i<wrqu->data.length;i++){
		if(extra[i] == ',')
			extra[i] =' ';
	}

	if(extra[0] == ' '){
		atbm_printk_err("invalid parameter!\n");
		atbm_kfree(extra);
		return -EINVAL;
	}
	printk("exttra = %s  %d\n", extra, wrqu->data.length);
	fwcmd_common_deal(sdata,extra,wrqu->data.length);

	i = 0;
	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			atbm_printk_wext("exttra = %s\n", extra);
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,
				extra, wrqu->data.length, vif->if_id));
			break;
		}
	}
	atbm_kfree(extra);
	return ret;
	
}
#ifdef CONFIG_ATBM_ETF_OLD
static int atbm_ioctl_start_tx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = 0;
	int len = 0;
	int packet_len = 0;
//	int num = 0;
//	int flag = 0;
	int channel = 0;
	u32 is_40M = 0;
	int rate10x = 0;
	int greedfiled = 0;
	int precomp_sel = 0;
	char *delim = "cfg:";
	char *pthreshold = NULL;
	char *extra = NULL;
	const char *pos = NULL;
	const char *pos_end = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_sub_if_data *sdata_tmp = NULL;
	
	struct atbm_vif *priv;// = ABwifi_get_vif_from_ieee80211(&sdata->vif);
	struct ieee80211_internal_etf_request  tx_param;
	//atbm_printk_err("start tx join status [%d] \n",priv->join_status);
	memset(&tx_param,0,sizeof(struct ieee80211_internal_etf_request));
	list_for_each_entry(sdata_tmp, &local->interfaces, list){
	    if (sdata_tmp->vif.type == NL80211_IFTYPE_AP){
		 		atbm_printk_err("driver run ap mode! not allow start tx! \n");
	             return -EINVAL;
	    }
	    if(sdata_tmp->vif.type == NL80211_IFTYPE_MONITOR){
				atbm_printk_err("driver run monitor mode! not allow start tx! \n");
                 return -EINVAL;
		}
		priv = ABwifi_get_vif_from_ieee80211(&sdata_tmp->vif);
		if(priv->join_status == 4){
			atbm_printk_err("driver on  sta mode connect ap! not allow start tx! \n");
			return -EINVAL;
		}
    }


	if(!(extra = atbm_kmalloc(wrqu->data.length + 1, GFP_KERNEL)))
		return -ENOMEM;
	
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length)) != 0){
		atbm_kfree(extra);
		return -EINVAL;
	}

	atbm_printk_wext("atbm_ioctl_start_tx:%s\n",extra);
	if(wrqu->data.length < 10){
		atbm_printk_err("need to input parameters\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 start_tx channel,rate,len,is_40M,greedfiled\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 start_tx 1,1,300,1\n");
		return -EINVAL;
	}

	pthreshold = strstr(extra, delim);
	if(pthreshold)
	{
		memcpy(tx_param.threshold_param, pthreshold, strlen(pthreshold));
		memset(pthreshold, 0, strlen(pthreshold));
		atbm_printk_wext("**extra:%s**\n", extra);
		atbm_printk_wext("**threshold_param:%s**\n", tx_param.threshold_param);
	}

	extra[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(extra[i] == ',')
			extra[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(extra,wrqu->data.length+1);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - extra);

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos+1;
	
	/*
	*channel
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,channel,atbm_accsii_to_int,false,exit,ret);

	/*
	*rate10x
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,rate10x,atbm_accsii_to_int_10x,false,exit,ret);

	/*
	*len
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,packet_len,atbm_accsii_to_int,false,exit,ret);

	/*
	*is40M
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,is_40M,atbm_accsii_to_int,false,exit,ret);

	/*
	*greedfiled
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,greedfiled,atbm_accsii_to_int,false,exit,ret);

	if(len)
	{
		/*
		*precomp_sel
		*/
		ATBM_WEXT_PROCESS_PARAMS(pos,len,precomp_sel,atbm_accsii_to_int,false,exit,ret);
		if((precomp_sel != 0) && (precomp_sel != 1)){
			atbm_printk_err("invalid precomp_sel or precomp_sel %d\n",precomp_sel);
			atbm_kfree(extra);
			return -EINVAL;
		}
	}

	if((is_40M != 0) && (is_40M != 1)){
			atbm_printk_err("invalid 40M or 20M %d\n",is_40M);
			atbm_kfree(extra);
			return -EINVAL;
	}

	if((greedfiled != 0) && (greedfiled != 1)){
			atbm_printk_err("invalid greedfiled %d\n",greedfiled);
			atbm_kfree(extra);
			return -EINVAL;
	}
	
	//check channel
	if(channel <= 0 || channel > 14){
		atbm_printk_err("invalid channel!\n");
		atbm_kfree(extra);
		return -EINVAL;
	}
	//printk("rate===%d\n",rate);
	tx_param.channel = channel;
	tx_param.rate = rate10x;
	tx_param.channel_type = is_40M;
	tx_param.len = packet_len;
	tx_param.greedfiled = greedfiled;
	tx_param.precomp_sel = precomp_sel;
	ret = atbm_internal_start_tx(sdata,&tx_param);

exit:

	atbm_kfree(extra);
	return ret;
}

static int atbm_ioctl_stop_tx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
//	int i = 0;
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
//	struct ieee80211_local *local = sdata->local;
//	struct atbm_common *hw_priv=local->hw.priv;

//	struct atbm_vif *vif;
	
	if(wrqu->data.length > 1){
		atbm_printk_err("redundant parameters,please try again!\n");
		//return -EINVAL;
	}
	ret = atbm_internal_stop_tx(sdata);
	return ret;
}

#else

}
static int atbm_ioctl_start_tx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	char *extra  = NULL;
	int ret = 0;
	struct ieee80211_internal_etf_request *request = NULL;
	char *delim = "cfg:";
	const char *pos = NULL;
	const char *pos_end = NULL;
	int len = 0;
	int i = 0;
	struct atbm_decimal_fraction rate;
	
	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_wext("%s:%d\n",__func__,__LINE__);
		ret = -ENETDOWN;
		goto exit;
	}
	
	if(!(extra = atbm_kmalloc(wrqu->data.length + 1, GFP_KERNEL))){
		ret = -ENOMEM;
		goto exit;
	}
	
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length)) != 0){
		goto  exit;
	}
	
	atbm_printk_wext("atbm_ioctl_start_tx:%s\n",extra);
	if(wrqu->data.length < 10){
		atbm_printk_err("need to input parameters\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 start_tx channel,rate,len,is_40M,greedfiled\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 start_tx 1,1,300,1\n");
		ret = -EINVAL;
		goto  exit;
	}

	request = atbm_internal_etf_request_alloc(0);

	if(request == NULL){
		ret = -ENOMEM;
		goto  exit;
	}

	pos = strstr(extra, delim);
	if(pos){
		memcpy(request->threshold_param, pos, strlen(pos));
		memset(pos, 0, strlen(pos));
		atbm_printk_wext("**extra:%s**\n", extra);
		atbm_printk_wext("**threshold_param:%s**\n", request->threshold_param);
	}

	extra[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(extra[i] == ',')
			extra[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(extra,wrqu->data.length+1);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - extra);

		if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos+1;
	/*
	*channel
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,request->channel,atbm_accsii_to_int,false,exit,ret);
	
	if(ieee8011_channel_valid(&local->hw,request->channel) == false){
		atbm_printk_err("%s:channel[%d] is wrong\n",__func__,request->channel);
		ret = -EINVAL;
		goto exit;
	}
	/*
	*rate
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,rate,atbm_accsii_to_decimal,false,exit,ret);
	if(rate.digits > 1){
		ret = -EINVAL;
		goto exit;
	}
	rate.interger = rate.interger * 10 + rate.decimal;
	
	/*
	*len
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,request->len,atbm_accsii_to_int,false,exit,ret);
	/*
	*channel_type
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,request->channel_type,atbm_accsii_to_int,false,exit,ret);
	/*
	*greedfiled
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,request->greedfiled,atbm_accsii_to_int,false,exit,ret);

	/*
	*precomp_sel
	*/
	if(len != 0)
		ATBM_WEXT_PROCESS_PARAMS(pos,len,request->precomp_sel,atbm_accsii_to_int,false,exit,ret);

	
	ret = atbm_internal_start_tx(sdata,request);
	
exit:
	if(extra)
		atbm_kfree(extra);
	if(request)
		atbm_internal_etf_request_put(request);
	return ret;
}

static int atbm_ioctl_stop_tx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	
	return atbm_internal_stop_tx(sdata);
}

#endif

static int atbm_ioctl_start_rx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = 0;
	int is_40M = 0;
	int channel = 0;
	char *extra = NULL;
	char *is_40M_p = NULL;
//	char cmd[20] = "monitor 1 ";
//	u8 ucDbgPrintOpenFlag = 1;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
//	struct atbm_common *hw_priv=local->hw.priv;
//	struct atbm_vif *vif;

	struct ieee80211_sub_if_data *sdata_tmp = NULL;
	struct atbm_vif *priv;
	list_for_each_entry(sdata_tmp, &local->interfaces, list){
             if (sdata_tmp->vif.type == NL80211_IFTYPE_AP){
			 		atbm_printk_err("driver run ap mode! not allow start rx! \n");
                     return -EINVAL;
             }
			 if(sdata_tmp->vif.type == NL80211_IFTYPE_MONITOR){
					atbm_printk_err("driver run monitor mode! not allow start rx! \n");
                     return -EINVAL;
			 }
			 priv = ABwifi_get_vif_from_ieee80211(&sdata_tmp->vif);
			if(priv->join_status == 4){
				atbm_printk_err("driver on  sta mode connect ap! not allow start tx! \n");
				return -EINVAL;
			}
    }




	//./iwpriv wlan0 fwdbg 1
	

	if(wrqu->data.length <= 3){
		atbm_printk_err("need to input parameters\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 start_rx 1,0\n");
		return -EINVAL;
	}

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL)))
		return -EINVAL;

	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length)) != 0){
		atbm_kfree(extra);
		return -EINVAL;
	}

	for(i=0;extra[i] != ',';i++){
		if(extra[i] == ','){
			break;
		}
		channel = channel * 10 +(extra[i] - 0x30);
	}

	for(i=0;i<wrqu->data.length;i++){
			if(extra[i] == ','){
				is_40M_p = extra +i + 1;
				break;
			}	
		}

	if((NULL == is_40M_p) || (is_40M_p[0] == '\0')){
		atbm_printk_err("invalid channnel type\n");
		atbm_printk_err("is_40M value: 1:40M,0:20M\n");
		atbm_kfree(extra);
		return -EINVAL;
	}

	for(i=0;is_40M_p[i] != '\0';i++){
		if(1 == i){
			atbm_printk_err("invalid channel type!\n");
			atbm_printk_err("is_40M value: 1:40M,0:20M\n");
			atbm_kfree(extra);
			return 	-EINVAL;
		}
		is_40M = is_40M * 10 + (is_40M_p[i] - 0x30);
	}

	atbm_printk_wext("is_40M:%d\n", is_40M);
	if((is_40M != 0) && (is_40M != 1)){
		atbm_kfree(extra);
		atbm_printk_err("invalid 40M or 20M\n");
		return -EINVAL;
	}
	
	if(channel <= 0 || channel > 14){
			atbm_kfree(extra);
			atbm_printk_err("invalid channel!\n");
			return -EINVAL;
		}
/*
	for(i=0;i<wrqu->data.length;i++){
		if(extra[i] == ',')
			extra[i] =' ';
	}
*/	
	ret = atbm_internal_start_rx(sdata,channel,is_40M);

	

	if(extra)
		atbm_kfree(extra);
	return ret;
}


static int atbm_ioctl_stop_rx(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{

	int ret = 0;
//	int len = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
//	struct ieee80211_local *local = sdata->local;
//	struct atbm_common *hw_priv=local->hw.priv;
	fixed_freq_rx_data status;

	
	memset(&status,0,sizeof(fixed_freq_rx_data));

	
	if(wrqu->data.length > 1){
		atbm_printk_err("redundant parameters, please try again!\n");

	}
	ret = atbm_internal_stop_rx(sdata,&status);
	if(ret < 0){
		atbm_printk_err("atbm_ioctl_stop_rx : stop_rx err! \n");
		goto exit;
	}
		
	

	if(ext){
		memcpy(ext,status.status_data ,status.len);	
		wrqu->data.length = status.len + 1;
	}

exit:
	return ret;
}

#ifdef CONFIG_ATBM_IWPRIV_USELESS
static int atbm_ioctl_get_rx_stats(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int ret = 0;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;
	int i = 0;
	
	if(!(extra = atbm_kmalloc(16, GFP_KERNEL)))
		return -ENOMEM;

	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}

	atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_read_mib(hw_priv, WSM_MIB_ID_GET_ETF_RX_STATS,
						extra, 16, vif->if_id));
					break;
				}
			}

	if((ret = copy_to_user(wrqu->data.pointer, extra, 16)) != 0){
		atbm_kfree(extra);
		return -EINVAL;
	}
	atbm_kfree(extra);
	return ret;
}
#endif
static int atbm_ioctl_set_rts(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = 0;
	int value = 0;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;

	if(wrqu->data.length <= 1){
		atbm_printk_err("need parameter,please try again!\n");
		return -EINVAL;
	}

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL)))
		return -EINVAL;
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}

	if(!(memcmp(extra, "show", wrqu->data.length))){
		atbm_printk_err("get_rts_threshold = %d\n", atbm_tool_rts_threshold);
		atbm_kfree(extra);
		return ret;
	}
	else{
		for(i=0;extra[i] != '\0';i++){
			value = value * 10 + (extra[i] - 0x30);
		}

		if((value <0 ) || (value >= 2048)){
			atbm_printk_err("invalid parameter!\n");
			atbm_kfree(extra);
			return -EINVAL;
		}
		
		atbm_printk_wext("set_rtsthr is %d\n", value);
		atbm_for_each_vif(hw_priv,vif,i){
			if(vif != NULL)
			{
				__le32 val32;
				if (value != (u32) -1)
					val32 = __cpu_to_le32(value);
				else
					val32 = 0; /* disabled */

				/* mutex_lock(&priv->conf_mutex); */
				ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_RTS_THRESHOLD,
					&val32, sizeof(val32), vif->if_id));
				atbm_tool_rts_threshold = val32;
				break;
			}
		}
	}
	atbm_kfree(extra);
	return ret;
}

static int atbm_ioctl_ctl_gi(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int ret = 0;
	int value = 0;
	char *extra = NULL;
	atbm_printk_wext("@@@@@@@ atbm_ioctl_ctl_gi()\n");

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}

	if((wrqu->data.length <= 1) || (wrqu->data.length > 2)){
		atbm_kfree(extra);
		atbm_printk_err("invalid parameter,please try again!\n");
		return -EINVAL;
	}

	value = *extra - 0x30;
	if((value < 0 ) || (value > 1)){
		atbm_kfree(extra);
		atbm_printk_err("invalid parameter,parameter must be 1 or 0\n");
		return -EINVAL;
	}
	atbm_printk_wext("set_short_gi(%d)\n", value);
	atbm_set_shortGI(value);
	atbm_tool_shortGi = value;
	atbm_kfree(extra);
	return ret;
}

#if 0
static int atbm_ioctl_setmac(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	int index;
	u8 macAddr[6] = {0};
	u8 extraBuff[18] = {0};
	int ret = -EINVAL;
#define   isHex(value)  	(((value > '9') && (value < '0')) && \
							 ((value > 'f') && (value < 'a')) && \
							 ((value > 'F') && (value < 'A')))
	memcpy(extraBuff, extra, 17);
	extraBuff[17] = ':';
	for (index  = 0 ; index < 17; index+= 3)
	{
		if (isHex(extraBuff[index]))
		{
					
			atbm_printk_err("mac addr format error\n");
			return -EINVAL;
		}
		if (isHex(extraBuff[index + 1]))
		{
					
			atbm_printk_err( "mac addr format error\n");
			return -EINVAL;
		}
		
		if (extraBuff[index + 2] != ':')
		{
			atbm_printk_err("mac addr format error\n");
			return -EINVAL;
		}
		
	}

#undef isHex

	sscanf(extraBuff, "%x:%x:%x:%x:%x:%x", (int *)&macAddr[0], (int *)&macAddr[1], (int *)&macAddr[2], (int *)&macAddr[3], (int *)&macAddr[4], (int *)&macAddr[5]);

	if (local->ops != NULL)
	{
		ret = local->ops->set_mac_addr2efuse(&local->hw, macAddr);
	}

	return ret;
}
#endif
static int atbm_ioctl_get_Last_mac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	//int index;
	u8 macAddr[6] = {0};
	//u8 extraBuff[18] = {0};
	int ret = -EINVAL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
/*
	if(wrqu->data.length > 1){
		atbm_printk_err("command 'getmac' need not parameters\n");
		return ret;
	}
*/
	if ((ret = wsm_get_efuse_last_mac(hw_priv, &macAddr[0])) == 0){
		if(extra){
			sprintf(extra,"macAddr:%02x:%02x:%02x:%02x:%02x:%02x\n", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
			wdata->data.length = strlen(extra);
		}
		atbm_printk_err("macAddr:%02x:%02x:%02x:%02x:%02x:%02x\n", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
		//return ret;
	}
	else{
		if(extra){
			sprintf(extra,"read mac address failed\n");
			wdata->data.length = strlen(extra);
		}
		atbm_printk_err("read mac address failed\n");
		return ret;
	}
	//if(extra){
		//memcpy((u8 *)extra, (u8*)macAddr, 6);
	//	wdata->data.length = strlen(extra);
	//}
	return ret;
}

static int atbm_ioctl_get_First_mac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	//int index;
	u8 macAddr[6] = {0};
	//u8 extraBuff[18] = {0};
	int ret = -EINVAL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
/*
	if(wrqu->data.length > 1){
		atbm_printk_err("command 'getmac' need not parameters\n");
		return ret;
	}
*/
	if ((ret = wsm_get_efuse_first_mac(hw_priv, &macAddr[0])) == 0){
		if(extra){
			sprintf(extra,"macAddr:%02x:%02x:%02x:%02x:%02x:%02x\n", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
			wdata->data.length = strlen(extra);
		}
		atbm_printk_err("macAddr:%02x:%02x:%02x:%02x:%02x:%02x\n", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
		//return ret;
	}
	else{
		if(extra){
			sprintf(extra,"read mac address failed\n");
			wdata->data.length = strlen(extra);
		}
		atbm_printk_err("read mac address failed\n");
		return ret;
	}
	//if(extra){
		//memcpy((u8 *)extra, (u8*)macAddr, 6);
		//wdata->data.length = strlen(extra);
	//}
	return ret;
}

static int atbm_ioctl_getmac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	//int index;
	u8 macAddr[6] = {0};
	//u8 extraBuff[18] = {0};
	int ret = -EINVAL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;

	if(wrqu->data.length > 1){
		atbm_printk_err("command 'getmac' need not parameters\n");
		return ret;
	}

	if ((ret = wsm_get_mac_address(hw_priv, &macAddr[0])) == 0){
		atbm_printk_err("macAddr:%02x:%02x:%02x:%02x:%02x:%02x\n", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
		//return ret;
	}
	else{
		atbm_printk_err("read mac address failed\n");
		return ret;
	}
	if(copy_to_user(wdata->data.pointer, macAddr, 6) != 0){
		ret = -EINVAL;
		//goto exit;
	}
	return ret;
}


#ifdef CONFIG_ATBM_START_WOL_TEST
static int atbm_ioctl_start_wol(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i;
	int ret = 0;
	int value = 0;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif;



	if (!sdata->u.mgd.associated){
		printk("%s %d\n",__func__,__LINE__);
		return -EINVAL;	
	}

/*
	if(sdata->vif.rekey_set == 0){
		atbm_printk_err("key data not set\n");
		return -EINVAL;	
	}
*/

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}

	if((wrqu->data.length <= 1) || (wrqu->data.length > 2)){
		atbm_printk_err("invalid parameter,please try again!\n");
		atbm_kfree(extra);
		return -EINVAL;
	}

	value = *extra - 0x30;
	if((value < 0 ) || (value > 1)){
		atbm_printk_err("invalid parameter,parameter must be 1 or 0\n");
		atbm_kfree(extra);
		return -EINVAL;
	}
	atbm_printk_wext("start wol func(%d)\n", value);
	atbm_for_each_vif(hw_priv,vif,i){
		if(vif != NULL)
		{
			__le32 val32;
			if (value != (u32) -1)
				val32 = __cpu_to_le32(value);
			else
				val32 = 0; /* disabled */
			drv_set_rekey_data(sdata->local,sdata,val32);
			ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_START_WOL,
				&val32, sizeof(val32), vif->if_id));
			break;
		}
	}
	atbm_kfree(extra);
	return ret;

}
#endif
#define MAC2STR(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#ifdef ATBM_PRIVATE_IE
/*
*1, SSTAR_INSERT_USERDATA_CMD    	
*	ioctl(global->ioctl_sock, SSTAR_INSERT_USERDATA_CMD, &user_data)
*	
*   update special ie to beacon,probe response and probe request ,if possible 
*/
static int atbm_ioctl_ie_insert_user_data(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_sub_if_data *sdata_update;
	u8 atbm_oui[4]={0x41,0x54,0x42,0x4D};
	
	int ret = 0;
	char *special = NULL;
	int len = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	len = wdata->data.length-1;

	if((len<0)||(len>255)){
		atbm_printk_err("ErrMsg: data too long\n");
		ret = -EINVAL;
		goto exit;
	}

	special = atbm_kzalloc(len+4, GFP_KERNEL);

	if(special == NULL){
		ret = -EINVAL;
		goto exit;
	}
	
	memcpy(special,atbm_oui,4);
	
	if(copy_from_user(special+4, wdata->data.pointer, len)){
		atbm_printk_err("[IE] copy_from_user fail\n");
		ret = -ENODATA;
		goto exit;
	}
	atbm_printk_always("[IE]:%s\n",special);
	list_for_each_entry(sdata_update, &local->interfaces, list){
		bool res = true;
		
		if(!ieee80211_sdata_running(sdata_update)){
			continue;
		}

		if(sdata_update->vif.type == NL80211_IFTYPE_STATION){
			res = ieee80211_ap_update_special_probe_request(sdata_update,special,len+4);
		}else if((sdata_update->vif.type == NL80211_IFTYPE_AP)&&
		         (rtnl_dereference(sdata_update->u.ap.beacon))){
		    res = ieee80211_ap_update_special_beacon(sdata_update,special,len+4);
			if(res == true){
				res = ieee80211_ap_update_special_probe_response(sdata_update,special,len+4);
			}
		}
		if(res == false){
			atbm_printk_err("[IE] insert failed\n");
			ret = -EOPNOTSUPP;
			goto exit;
		}
	}
exit:
	if(special)
		atbm_kfree(special);
	return ret;
}

int hex2digit(int c)
{
	if('0'<=c && c<='9')
		return c-'0';
	if('A'<=c && c<='F')
		return c-('A'-10);
	if('a'<=c && c<='f')
		return c-('a'-10);
	return -1;
}

/*
*1, SSTAR_INSERT_USERDATA_CMD    	
*	ioctl(global->ioctl_sock, SSTAR_INSERT_USERDATA_CMD, &user_data)
*	
*   update special ie to beacon,probe response and probe request ,if possible 
*/
static int atbm_ioctl_ie_insert_vendor_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_sub_if_data *sdata_update;
	u8 atbm_oui[4]={0x41,0x54,0x42,0x4D};
	
	int ret = 0;
	char *extra = NULL;
	char *ie_str =NULL;
	int ie_str_len;
	u8 vendor_ie[255];
	int i,j;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL);

	if(extra == NULL){
		ret =  -ENOMEM;
		goto exit;
	}

	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		ret = -EINVAL;
		goto exit;
	}
	
	extra[wrqu->data.length] = 0;
	
	for(i=0; i<wrqu->data.length; i++){
		if(extra[i] == ','){
			ie_str = &extra[i+1];
			break;
		}
	}
	
	ie_str_len = wrqu->data.length - i - 2;
	if((ie_str_len <= 0) || (ie_str_len > 251*2) || (ie_str_len%2)){
		atbm_printk_err("ErrMsg: vendor_ie_len err(%d)\n", ie_str_len);
		ret = -EINVAL;
		goto exit;
	}

	atbm_printk_always("VENDOR IE:%s,LEN:%d\n",ie_str,ie_str_len);

	for(i=0;i<ie_str_len;i++){
		ret = hex2digit(ie_str[i]);
		if(ret < 0){
			atbm_printk_err("ErrMsg: ie payload format err\n");
			ret = -EINVAL;
			goto exit;
		}
		ie_str[i] = ret;
	}
	
	memcpy(vendor_ie, atbm_oui, 4);
	for(i=0,j=0; j<ie_str_len/2; i+=2,j++){
		vendor_ie[j+4] = ie_str[i+1] | (ie_str[i]<<4);
	}

	list_for_each_entry(sdata_update, &local->interfaces, list){
		bool res = true;
		
		if(!ieee80211_sdata_running(sdata_update)){
			continue;
		}

		res = ieee80211_ap_update_vendor_probe_request(sdata_update,vendor_ie,ie_str_len/2+4);
#if 0
		if(sdata_update->vif.type == NL80211_IFTYPE_STATION){
			res = ieee80211_ap_update_special_probe_request(sdata_update,special,len+4);
		}else if((sdata_update->vif.type == NL80211_IFTYPE_AP)&&
		         (rtnl_dereference(sdata_update->u.ap.beacon))){
		    res = ieee80211_ap_update_special_beacon(sdata_update,special,len+4);
			if(res == true){
				res = ieee80211_ap_update_special_probe_response(sdata_update,special,len+4);
			}
		}
#endif
		if(res == false){
			atbm_printk_err("[IE] insert failed\n");
			ret = -EOPNOTSUPP;
			goto exit;
		}
	}	
exit:
	if(extra)
		atbm_kfree(extra);	
	return ret;
}


/*
*2,  SSTAR_GET_USERDATA_CMD    			
*	ioctl(global->ioctl_sock, SSTAR_INSERT_USERDATA_CMD, &user_data)
*	get special ie of the received beacon
*/
static bool atbm_handle_special_ie(struct ieee80211_hw *hw,struct atbm_internal_scan_results_req *req,struct ieee80211_internal_scan_sta *sta)
{
	u8 *special_ie = (u8*)req->priv;
	u8 *pos = NULL;
	u8 atbm_oui[4]={0x41,0x54,0x42,0x4D};//ATBM
	
	if(req->n_stas >= MAC_FILTER_NUM){
		return false;
	}

	pos = special_ie + (req->n_stas*USER_DATE_LEN);

	if(sta->ie&&sta->ie_len){
		if(memcmp(sta->ie,atbm_oui,4) == 0){
			if((sta->ie_len>4)){
				memcpy(pos,sta->ie+4,sta->ie_len-4);
				req->n_stas++;
			}
		}else {
			memcpy(pos,sta->ie,sta->ie_len);
			req->n_stas++;
		}
	}
	return true;
}
static int atbm_ioctl_ie_get_user_data(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	int ret = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct atbm_internal_scan_results_req req;
	u8 *special_ie = NULL;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	special_ie = atbm_kzalloc(MAC_FILTER_NUM*USER_DATE_LEN, GFP_KERNEL);

	if(special_ie == NULL){
		ret = -EINVAL;
		goto exit;
	}

	req.flush = true;
	req.priv  = special_ie;
	req.result_handle  = atbm_handle_special_ie;
	req.n_stas = 0;
	ieee80211_scan_internal_req_results(local,&req);
	atbm_printk_always("ie:%s\n",special_ie);
	if(copy_to_user(wdata->data.pointer, special_ie, USER_DATE_LEN*MAC_FILTER_NUM) != 0){
		ret = -EINVAL;
		goto exit;
	}
	
exit:
	if(special_ie)
		atbm_kfree(special_ie);
	
	return ret;
}


/*
*3,  SSTAR_SEND_MSG_CMD       		     
*    ioctl(global->ioctl_sock, SSTAR_SEND_MSG_CMD, &Wifi_Send_Info_t)
*
*    triger scan
*/
static int atbm_ioctl_ie_send_msg(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;
	int len = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	Wifi_Send_Info_t *send_info = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_internal_scan_request internal_scan;
	u8 channel = 0;
	
	memset(&internal_scan,0,sizeof(struct ieee80211_internal_scan_request));

	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		ret = -EOPNOTSUPP;
		goto exit;
	}

	len = wdata->data.length-1;

	if(len>0){
		
		send_info = (Wifi_Send_Info_t *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
		if(send_info == NULL){
			ret =  -ENOMEM;
			goto exit;
		}
		if(copy_from_user((void *)send_info, wdata->data.pointer, wdata->data.length)){
			ret =  -EINVAL;
			goto exit;
		}

		if(send_info->mac_filter){
			u8 i = 0;
			internal_scan.macs = atbm_kzalloc(MAC_FILTER_NUM*sizeof(struct ieee80211_internal_mac), GFP_KERNEL);

			if(internal_scan.macs == NULL){
				ret =  -EINVAL;
				goto exit;
			}

			for(i = 0;i<MAC_FILTER_NUM;i++){
				memcpy(internal_scan.macs[i].mac,send_info->Bssid[i],6);
			}
			internal_scan.n_macs = MAC_FILTER_NUM;
		}
		channel = send_info->channel;
	}else {
	}

	if(channel != 0){
		internal_scan.channels = &channel;
		internal_scan.n_channels = 1;
	}
    if(atbm_internal_cmd_scan_triger(sdata,&internal_scan) == false){
		ret =  -ENOMEM;
		goto exit;
    }
exit:
	if(send_info)
		atbm_kfree(send_info);
	if(internal_scan.macs)
		atbm_kfree(internal_scan.macs);
	return ret;
}
static bool atbm_handle_scan_sta(struct ieee80211_hw *hw,struct atbm_internal_scan_results_req *req,struct ieee80211_internal_scan_sta *sta)
{
	Wifi_Recv_Info_t *info     = (Wifi_Recv_Info_t *)req->priv;
	Wifi_Recv_Info_t *pos_info = NULL;
	u8 atbm_oui[4]={0x41,0x54,0x42,0x4D};//ATBM
	
	if(req->n_stas >= MAC_FILTER_NUM){
		return false;
	}
#ifndef SIGMASTAR_FILTER_MACADDR_ONLY
	atbm_printk_debug("%s:ssid[%s] ie_len(%d)\n",__func__,sta->ssid,sta->ie_len);
	if((sta->ie == NULL) || (sta->ie_len == 0))
		return true;
#endif
	if(sta->ie && sta->ie_len){	
		atbm_printk_debug("%s:ie[%s] ie_len(%d)\n",__func__,sta->ie,sta->ie_len);
		//if(memcmp(sta->ie,atbm_oui,4) || (sta->ie_len < 4))
		if(sta->ie_len == 0)
			return true;
	}
	
	pos_info = info+req->n_stas;
	req->n_stas ++;
	pos_info->channel = sta->channel;
	pos_info->Rssi = sta->signal;
	memcpy(pos_info->Bssid,sta->bssid,6);
	if(sta->ssid_len && sta->ssid)
		memcpy(pos_info->Ssid,sta->ssid,sta->ssid_len);
	if(sta->ie && sta->ie_len){
		if((sta->ie_len >= 4) && (memcmp(sta->ie,atbm_oui,4) == 0))
			memcpy(pos_info->User_data,sta->ie+4,sta->ie_len-4);
		else
			memcpy(pos_info->User_data,sta->ie,sta->ie_len);
	}
	return true;
}

/*
*4,  SSTAR_RECV_MSG_CMD       
*	 ioctl(global->ioctl_sock, SSTAR_RECV_MSG_CMD, &Wifi_Recv_Info_t)
*	 get the received beacon and probe response
*/
static int atbm_ioctl_ie_recv_msg(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	u8 *recv_info = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct atbm_internal_scan_results_req req;
	int ret = 0;

	req.flush = false;
	req.n_stas = 0;
	req.priv   = NULL;
	req.result_handle = NULL;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	recv_info = atbm_kzalloc(sizeof(Wifi_Recv_Info_t)*MAC_FILTER_NUM, GFP_KERNEL);

	if(recv_info == NULL){
		ret =  -ENOMEM;
		goto exit;
	}

	req.flush = true;
	req.n_stas = 0;
	req.priv = recv_info;
	req.result_handle = atbm_handle_scan_sta;

	ieee80211_scan_internal_req_results(sdata->local,&req);

	if(copy_to_user((void *)wdata->data.pointer, recv_info, MAC_FILTER_NUM*sizeof(Wifi_Recv_Info_t)) != 0){
		ret = -EINVAL;
	}
exit:
	if(recv_info)
		atbm_kfree(recv_info);
	return ret;
}
static int atbm_ioctl_ie_ipc_clear_insert_data(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
        int ret = 0;

        struct ieee80211_sub_if_data *sdata = NULL;

        if(dev == NULL){
                printk("[IE] atbm_ioctl_ie_ipc_reset() dev NULL\n");
                return -1;
        }

        sdata = IEEE80211_DEV_TO_SUB_IF(dev);

        if(sdata == NULL){
                atbm_printk_err("[IE] atbm_ioctl_ie_ipc_reset() sdata NULL\n");
                return -1;
        }
		if(!ieee80211_sdata_running(sdata)){
			return -ENETDOWN;
		}
   

        atbm_printk_err("[IE] atbm_ioctl_ie_ipc_clear_insert_data()\n\n");
     	{
                
			struct ieee80211_local *local = sdata->local;
			struct ieee80211_sub_if_data *sdata_update;
			list_for_each_entry(sdata_update, &local->interfaces, list){
				bool res = true;
				
				if(!ieee80211_sdata_running(sdata_update)){
					continue;
				}

				if(sdata_update->vif.type == NL80211_IFTYPE_STATION){
					res = ieee80211_ap_update_special_probe_request(sdata_update,NULL,0);
				}else if((sdata_update->vif.type == NL80211_IFTYPE_AP)&&
				         (rtnl_dereference(sdata_update->u.ap.beacon))){
				    res = ieee80211_ap_update_special_beacon(sdata_update,NULL,0);
					if(res == true){
						res = ieee80211_ap_update_special_probe_response(sdata_update,NULL,0);
					}
				}
				if(res == false){
					ret = -EOPNOTSUPP;
					return ret;
				}
			}
				
        }



        return ret;
		
}

#if 0
static int atbm_ioctl_ie_test(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;

	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	//struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	//struct atbm_vif *priv = ABwifi_hwpriv_to_vifpriv(hw_priv,0);
	Wifi_Send_Info_t send_info;
	char *ptr = NULL;
	unsigned short channel = 0;
	
	struct ieee80211_sub_if_data *sdata = NULL;
	struct atbm_vif *priv = NULL;
	
	if(dev == NULL){
		atbm_printk_err("[IE] atbm_ioctl_ie_test() dev NULL\n");
		return -1;
	}

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if(sdata == NULL){
		atbm_printk_err("[IE] atbm_ioctl_ie_test() sdata NULL\n");
		return -1;
	}
	

	priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
	if(atomic_read(&priv->enabled)==0){
		atbm_printk_err("[IE] atbm_ioctl_ie_test() priv is disabled\n");
		return -1;
	}	

	atbm_printk_wext("\n[IE] atbm_ioctl_ie_test()\n\n");

	if(sdata->vif.type == NL80211_IFTYPE_STATION){
		atbm_printk_wext("[IE] STA Test Start\n");
		if(!(ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL))){
			return -ENOMEM;
		}
		if((ret = copy_from_user(ptr, wdata->data.pointer, wdata->data.length))){
			atbm_kfree(ptr);
			return -EINVAL;
		}

		frame_hexdump("Test", ptr, 10);
		
		//channel = my_atoi(ptr);
		//channel = 3;
		//channel = *(unsigned short *)ptr;
		//memcpy(&channel, ptr, sizeof(unsigned short));
		channel = str2channel(ptr);
		atbm_printk_wext("[IE] channel is %d\n", channel);
		
		memset(&send_info, 0, sizeof(Wifi_Send_Info_t));
		
		send_info.channel = channel;

		if(copy_to_user(wdata->data.pointer, (char *)&send_info, sizeof(Wifi_Send_Info_t)) != 0){
			atbm_kfree(ptr);
			return -EINVAL;
		}
		wdata->data.length = sizeof(Wifi_Send_Info_t) + 1;
		
		atbm_ioctl_ie_send_msg(dev, info, (void *)wrqu, extra);
		atbm_kfree(ptr);
	}else{
		atbm_printk_wext("[IE] AP Test Start\n");
	}

	return ret;
}
#endif
#endif

static int atbm_ioctl_get_rssi(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct altm_wext_msg{
		int type;
		int value;
		char externData[256];
	}msg;
	
	struct _atbm_wifi_info_{
		int wext_rssi;
		u8	wext_mac[ETH_ALEN];
	}atbm_wifi_info[ATBMWIFI_MAX_STA_IN_AP_MODE];

	int i = 0,j = 0,len = 0;	
	int ret = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = NULL;
	struct ieee80211_local *local;
	struct atbm_vif *priv = NULL;
	struct atbm_common *hw_priv;	
	struct sta_info *sta;


	if(dev == NULL){
		atbm_printk_err("atbm_ioctl_get_rssi() dev NULL\n");
		return -1;
	}

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	if(sdata == NULL){
		atbm_printk_err("atbm_ioctl_get_rssi() sdata NULL\n");
		return -1;
	}

	local = sdata->local;
	if(local == NULL){
		atbm_printk_err("atbm_ioctl_get_rssi() local NULL\n");
		return -1;
	}
	
	mutex_lock(&local->iflist_mtx);

	priv = (struct atbm_vif *)sdata->vif.drv_priv;
	if(priv == NULL){
		atbm_printk_err("atbm_ioctl_get_rssi() priv NULL\n");
		return -1;
	}

	if(atomic_read(&priv->enabled)==0){
		atbm_printk_err("atbm_ioctl_get_rssi() priv is disabled\n");
		mutex_unlock(&local->iflist_mtx);
		return -1;
	}
	
	hw_priv = priv->hw_priv;
	if(hw_priv == NULL){
		atbm_printk_err("atbm_ioctl_get_rssi() hw_priv NULL\n");
		mutex_unlock(&local->iflist_mtx);
		return -1;
	}

	atbm_printk_wext("atbm_ioctl_get_rssi()\n");

	memset(&msg, 0, sizeof(msg));
	memset(atbm_wifi_info,0,sizeof(struct _atbm_wifi_info_)*ATBMWIFI_MAX_STA_IN_AP_MODE);

	rcu_read_lock();
		
	list_for_each_entry_rcu(sta, &local->sta_list, list) {

		if(sta != NULL){
			if (sta->sdata->vif.type == NL80211_IFTYPE_AP){
				atbm_printk_wext( "@@@ sta cnt %d, %zu\n", hw_priv->connected_sta_cnt, sizeof(atbm_wifi_info));
				
				atbm_wifi_info[i].wext_rssi = -atbm_ewma_read(&sta->avg_signal);//sta->last_signal;
				memcpy(atbm_wifi_info[i].wext_mac, sta->sta.addr, ETH_ALEN);
				atbm_printk_err( "%d get sta: rssi %d, "MACSTR"\n", i, atbm_wifi_info[i].wext_rssi, MAC2STR(atbm_wifi_info[i].wext_mac));
				
				++i;
			}else{
				msg.value = -atbm_ewma_read(&sta->avg_signal);//sta->last_signal;
				atbm_printk_err( "atbm_ioctl_get_rssi() rssi %d\n", msg.value);
				break;
			}
		}

	}

	rcu_read_unlock();

	memcpy((u8*)msg.externData, (u8*)&atbm_wifi_info[0], sizeof(atbm_wifi_info));

/*	if(copy_to_user((u8 *)wdata->data.pointer+userdata_len, (u8*)(&msg), sizeof(msg)) != 0)
//	if( != 0)	
	{
		mutex_unlock(&local->iflist_mtx);
		return -EINVAL;
	}
	*/
	if(extra){
		if(sdata->vif.type == NL80211_IFTYPE_AP){
			for(j=0;j<i;j++){
				sprintf(extra + len,"\nmac:"MACSTR",rssi=%d\n",MAC2STR(atbm_wifi_info[j].wext_mac),atbm_wifi_info[j].wext_rssi);
				len=strlen(extra);
			}
			//memcpy((u8 *)extra, (u8*)(&msg), sizeof(msg));
			wdata->data.length = strlen(extra);
		}else{
			sprintf(extra,"\nrssi=%d\n",msg.value);
			wdata->data.length = strlen(extra);
		}
	}
	atbm_printk_wext("atbm_ioctl_get_rssi() size %zu , \n",wdata->data.length);
	mutex_unlock(&local->iflist_mtx);

	return ret;
}



extern unsigned int atbm_wifi_status_get(void);
#if 0
static int atbm_ioctl_get_wifi_state(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;
	unsigned char *ptr = NULL;
	unsigned int wifi_status = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	//struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	//struct ieee80211_local *local = sdata->local;
	//struct atbm_common *hw_priv=local->hw.priv;
	//struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;
	struct ieee80211_sub_if_data *sdata = NULL;
	struct atbm_vif *priv = NULL;
	
	if(dev == NULL){
		atbm_printk_err("[IE] atbm_ioctl_get_wifi_state() dev NULL\n");
		return -1;
	}

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if(sdata == NULL){
		atbm_printk_err("[IE] atbm_ioctl_get_wifi_state() sdata NULL\n");
		return -1;
	}
	
	mutex_lock(&sdata->local->iflist_mtx);
	
	priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
	if(atomic_read(&priv->enabled)==0){
		atbm_printk_err("[IE] atbm_ioctl_get_wifi_state() priv is disabled\n");
		mutex_unlock(&sdata->local->iflist_mtx);
		return -1;
	}
	
	ptr = wdata->data.pointer;

	//printk("atbm_ioctl_get_wifi_state()\n");

	//ap mode
	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		ret = -1;
		goto Error;
	}

	wifi_status = atbm_wifi_status_get();
	
	atbm_printk_err("%s , status = %d \n", wifi_status?"ASSOCIATED":"DISCONNECT",sdata->vif.bss_conf.ibss_joined);

	if(copy_to_user(ptr, (char *)&wifi_status, sizeof(unsigned int)) != 0){
		//mutex_unlock(&sdata->local->iflist_mtx);
		ret = -EINVAL;
	}

Error:	
	mutex_unlock(&sdata->local->iflist_mtx);
	return ret;

}
#else

static int atbm_ioctl_get_wifi_state(struct net_device *dev, struct iw_request_info *info,  union iwreq_data  *wrqu, char *extra)
{
	int ret = 0;
//	unsigned char *ptr = NULL;
	unsigned int wifi_status = 0;
//	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_if_managed *ifmgd=NULL;
	struct ieee80211_sub_if_data *sdata = NULL,*sdata_tmp = NULL;
	struct sta_info *sta = NULL;
	struct ieee80211_local *local = NULL;
	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	local = sdata->local;
	
	list_for_each_entry(sdata_tmp, &local->interfaces, list){
		if (sdata_tmp->vif.type != NL80211_IFTYPE_STATION){
			continue;
		}

		if(!ieee80211_sdata_running(sdata_tmp)){
			continue;
		}

		sdata = sdata_tmp;
		
		ifmgd = &sdata->u.mgd;
	
		mutex_lock(&ifmgd->mtx);

		if(ifmgd->associated == NULL){
			mutex_unlock(&ifmgd->mtx);
			//goto unlock;
			continue;
		}
		
		rcu_read_lock();
		
		sta = sta_info_get(sdata,ifmgd->associated->bssid);
		
		if(sta){
			wifi_status = test_sta_flag(sta, WLAN_STA_AUTHORIZED);
			rcu_read_unlock();
			mutex_unlock(&ifmgd->mtx);
			break;
		//break;
		}
		
		rcu_read_unlock();
		mutex_unlock(&ifmgd->mtx);
		//break;
	}


	atbm_printk_err("%d\n",wifi_status);
	sprintf(extra,"\nwifi_status=%d\n",wifi_status);
	return ret;

}


#endif
static int atbm_ioctl_set_freq(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	int ret = 0;
	char *freq_info = NULL;
	char *pos;
	int len = 0;
	unsigned int channel_num;
	unsigned int freq;
	struct ieee80211_internal_set_freq_req req;

	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	len = wdata->data.length;

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	freq_info = atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);

	if(freq_info == NULL){
		ret = -EINVAL;
		goto exit;
	}

	if(copy_from_user(freq_info, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}

	pos = freq_info;
	
	CmdLine_GetInteger(&pos, &channel_num);
	CmdLine_GetInteger(&pos, &freq);
	if(freq == 0)
		req.set = false;
	else
		req.set = true;
	req.channel_num = (u16)channel_num;
	req.freq = freq;
	
	atbm_printk_wext("atbm: ch %d, freq %d\n", req.channel_num, req.freq);

	if(atbm_internal_freq_set(&sdata->local->hw,&req) == false){
		ret =  -EINVAL;
	}

	if(ret == 0)
		atbm_set_freq(sdata->local);
exit:
	if(freq_info)
		atbm_kfree(freq_info);
	return ret;
}



static int atbm_ioctl_set_txpw(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;
//	int len = 0;
	char *ptr = NULL, *free_pp = NULL;
	char cmd[32];
	unsigned int tx_pw;

	union iwreq_data *wdata = (union iwreq_data *)wrqu;

	struct ieee80211_sub_if_data *sdata = NULL;
	struct ieee80211_local *local = NULL;
	struct atbm_vif *priv = NULL;
	struct atbm_common *hw_priv= NULL;
	
	if(dev == NULL){
		atbm_printk_err("[IE] atbm_ioctl_set_txpw() dev NULL\n");
		return -1;
	}

	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if(sdata == NULL){
		atbm_printk_err("[IE] atbm_ioctl_set_txpw() sdata NULL\n");
		return -1;
	}
	
	mutex_lock(&sdata->local->iflist_mtx);
	local = sdata->local;
	hw_priv=local->hw.priv;
	
	priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
	if(atomic_read(&priv->enabled)==0){
		atbm_printk_err("[IE] atbm_ioctl_set_txpw() priv is disabled\n");
		mutex_unlock(&sdata->local->iflist_mtx);
		return -1;
	}

	atbm_printk_wext("atbm_ioctl_set_txpw()\n\n");

	if(!(ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL))){
		mutex_unlock(&sdata->local->iflist_mtx);
		return -ENOMEM;
	}
	if((ret = copy_from_user(ptr, wdata->data.pointer, wdata->data.length))){
		atbm_kfree(ptr);
		mutex_unlock(&sdata->local->iflist_mtx);
		return -EINVAL;
	}
	
	free_pp = ptr;

//	len = wdata->data.length-1;

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "set_txpower %s ", ptr);
	atbm_printk_wext("atbm: %s\n", cmd);
	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, cmd, strlen(cmd), priv->if_id);
	if(ret < 0)
		atbm_printk_err("atbm: txpw wsm write mib failed. \n");

	CmdLine_GetInteger(&ptr, &tx_pw);
	atbm_set_tx_power(hw_priv, (int)tx_pw);
	
	atbm_kfree(free_pp);
	mutex_unlock(&sdata->local->iflist_mtx);

	return ret;
}



static int atbm_ioctl_get_rate(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;
	char mac_addr[6];

	int sta_id = 0;
	
	unsigned char ptr[20]={0};
	unsigned int rate_val = 0;
	unsigned int ptr_len = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
	ptr_len = wdata->data.length - 1;
	atbm_printk_wext("atbm_ioctl_get_rate()  %d\n",ptr_len);

	//ap mode
	if (sdata->vif.type == NL80211_IFTYPE_AP && (ptr_len == 17)) {
		struct ieee80211_sta* sta;
		//clear mac addr buffer
		memset(mac_addr, 0, 6);
		if(copy_from_user(ptr, wdata->data.pointer, ptr_len)){
			atbm_printk_wext("%s() copy userspace data err!!\n",__func__);
			return -EINVAL;
		}
		//convert mac string to mac hex format
		str2mac(mac_addr, ptr);
		
		//according to mac hex, find out sta link id
		rcu_read_lock();
		sta = ieee80211_find_sta(&sdata->vif, mac_addr);
		if (sta)
			sta_id = sta->aid;
		rcu_read_unlock();
		atbm_printk_wext("atbm_ioctl_get_rate() sta_id %d\n", sta_id);
		wsm_write_mib(hw_priv, WSM_MIB_ID_GET_RATE, &sta_id, 1, priv->if_id);
	}

	wsm_read_mib(hw_priv, WSM_MIB_ID_GET_RATE, &rate_val, sizeof(unsigned int), priv->if_id);

	//convert bits/s
	rate_val = rate_val/2;
	atbm_printk_wext("rate: %d bits/s\n", rate_val);
	/*
	//memcpy(extra, (char *)&rate_val, sizeof(unsigned int));
	if(sdata->vif.type == NL80211_IFTYPE_AP){
		memcpy((char *)extra, (char *)&rate_val, sizeof(unsigned int));
		wdata->data.length = sizeof(unsigned int);
		atbm_printk_wext("STATION MAC : "MACSTR" \n",MAC2STR(mac_addr));
	}else */
	{
		if(copy_to_user((char *)wdata->data.pointer, (char *)&rate_val, sizeof(unsigned int)) != 0)
			return -EINVAL;

	}

	
	return ret;
}

static int atbm_ioctl_get_cur_max_rate(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0,i;
	char mac_addr[6];
	int sta_id = 0;
	unsigned char ptr[30]={0};
	unsigned char maxrate_id = 0;
	static unsigned char last_rate_id = 0;
	char *pmaxrate_val = NULL;
	unsigned int ptr_len = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
	ptr_len = wdata->data.length - 1;
	atbm_printk_wext("atbm_ioctl_get_rate()  %d\n",ptr_len);
	msleep(100);
	//ap mode
	if (sdata->vif.type == NL80211_IFTYPE_AP && (ptr_len == 29)) {
		struct ieee80211_sta* sta;
		//clear mac addr buffer
		memset(mac_addr, 0, 6);
		
		if(copy_from_user(ptr, wdata->data.pointer, ptr_len)){
			atbm_printk_wext("%s() copy userspace data err!!\n",__func__);
			return -EINVAL;
		}
		for(i=0;i<ptr_len;i++){
			 if(ptr[i] == ','){
				break;
			}
			
		}
		//convert mac string to mac hex format
		str2mac(mac_addr, &ptr[i+1]);
		rcu_read_lock();
		//according to mac hex, find out sta link id
		sta = ieee80211_find_sta(&sdata->vif, mac_addr);
		if (sta)
			sta_id = sta->aid;
		rcu_read_unlock();
		atbm_printk_wext("atbm_ioctl_get_rate() sta_id %d\n", sta_id);
		wsm_write_mib(hw_priv, WSM_MIB_ID_GET_RATE, &sta_id, 1, priv->if_id);
	}
	
	ret = wsm_read_mib(hw_priv, WSM_MIB_ID_GET_CUR_MAX_RATE, &maxrate_id, sizeof(unsigned char), priv->if_id);
	if((maxrate_id > 255)&&(last_rate_id))
		maxrate_id = last_rate_id;
	last_rate_id = maxrate_id;
	//convert bits/s
	switch(maxrate_id){
			case WSM_TRANSMIT_RATE_1:
				pmaxrate_val = "1M";
			break;
			case WSM_TRANSMIT_RATE_2:
				pmaxrate_val = "2M";
			break;
			case WSM_TRANSMIT_RATE_5:
				pmaxrate_val = "5.5M";
			break;
			case WSM_TRANSMIT_RATE_11:
				pmaxrate_val = "11M";
			break;
			case WSM_TRANSMIT_RATE_6:
				pmaxrate_val = "6M";
			break;
			case WSM_TRANSMIT_RATE_9:
				pmaxrate_val = "9M";
			break;
			case WSM_TRANSMIT_RATE_12:
				pmaxrate_val = "12M";
			break;
			case WSM_TRANSMIT_RATE_18:
				pmaxrate_val = "18M";
			break;
			case WSM_TRANSMIT_RATE_24:
				pmaxrate_val = "24M";
			break;
			case WSM_TRANSMIT_RATE_36:
				pmaxrate_val = "36M";
			break;
			case WSM_TRANSMIT_RATE_48:
				pmaxrate_val = "48M";
			break;
			case WSM_TRANSMIT_RATE_54:
				pmaxrate_val = "54M";
			break;
			case WSM_TRANSMIT_RATE_HT_6:
				pmaxrate_val = "6.5M";
			break;
			case WSM_TRANSMIT_RATE_HT_13:
				pmaxrate_val = "13M";
			break;
			case WSM_TRANSMIT_RATE_HT_19:
				pmaxrate_val = "19.5M";
			break;
			case WSM_TRANSMIT_RATE_HT_26:
				pmaxrate_val = "26M";
			break;
			case WSM_TRANSMIT_RATE_HT_39:
				pmaxrate_val = "39M";
			break;
			case WSM_TRANSMIT_RATE_HT_52:
				pmaxrate_val = "52M";
			break;
			case WSM_TRANSMIT_RATE_HT_58:
				pmaxrate_val = "58M";
			break;
			case WSM_TRANSMIT_RATE_HT_65:
				pmaxrate_val = "65M";
			break;
			default:
				pmaxrate_val = "invalid rate";
				atbm_printk_err("maxrate_id:%d,invalid rate!\n",maxrate_id);
				break;
		}
	if(maxrate_id < 255){
		atbm_printk_always("id:%d,rate: %s bits/s\n", maxrate_id, pmaxrate_val);
//	else
//		atbm_printk_always("id:%d,rate: %s bits/s\n", maxrate_id, pmaxrate_val);
	
		if(extra){	
			//atbm_printk_always("extra[%s],wrqu->data.length = %d \n",extra,wrqu->data.length);
			//memset(extra,0,wrqu->data.length);
			//memcpy(extra,pmaxrate_val,strlen(pmaxrate_val));	
			//wrqu->data.length = strlen(pmaxrate_val);
			sprintf(extra,"\nsend_rate:%sbps\n",pmaxrate_val);
			wrqu->data.length = strlen(extra);
		}
	}
	return ret;
}

#if 0
int atbm_ioctl_best_ch_start(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_internal_channel_auto_select_req req;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		ret = -EOPNOTSUPP;
		goto exit;
	}
	memset(&req,0,sizeof(struct ieee80211_internal_channel_auto_select_req));

	if(atbm_internal_channel_auto_select(sdata,&req) == false){
		ret = -EOPNOTSUPP;
	}
exit:
	return ret;
}
int atbm_ioctl_best_ch_scan_result(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_internal_channel_auto_select_results results;
	Best_Channel_Scan_Result scan_result;
	int i = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}

	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		ret = -EOPNOTSUPP;
		goto exit;
	}
	
	memset(&scan_result,0,sizeof(Best_Channel_Scan_Result));
	memset(&results,0,sizeof(struct ieee80211_internal_channel_auto_select_results));
	results.version = 0;//use version 0
	
	if(atbm_internal_channel_auto_select_results(sdata,&results) == false){
		ret = -EINVAL;
		goto exit;
	}

	for(i = 0;i<CHANNEL_NUM;i++){
		scan_result.channel_ap_num[i] = results.n_aps[i];
	}

	for(i = 0;i<CHANNEL_NUM;i++){
		scan_result.busy_ratio[i] = results.busy_ratio[i];
	}

	scan_result.suggest_ch = results.susgest_channel;

	if(copy_to_user(wdata->data.pointer, &scan_result, sizeof(scan_result)) != 0)
		ret = -EINVAL;
exit:
	return ret;
}
#endif
#if 1
/*
	support special channel channel 1~42 all channel SpecialFlag = 1	
	other 1~14 all channel 

*/
static int atbm_ioctl_best_ch_scan(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_internal_channel_auto_select_req req;
	struct ieee80211_internal_channel_auto_select_results results;
//	Best_Channel_Scan_Result scan_result;
	u8 i = 0,j=0,k=0,start_channel,end_channel;
	u8 all_channels[18]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,36,38,40,42};
//	bool support_special=false;
	u8 all_n_channels = 0;
	u8 *ignor_channels = NULL,*vaid_channels = NULL;
	struct BestChannelSelect{
		unsigned char start_channel;
		unsigned char end_channel;
		unsigned char SpecialFlag;
		Best_Channel_Scan_Result scan_result;
	};
	struct BestChannelSelect *BestCh = NULL;
	int ret = 0;
	
	unsigned char *ptr = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	
	if(!ieee80211_sdata_running(sdata)){
		atbm_printk_err("sdata is not running! \n");
		ret = -ENETDOWN;
		goto exit;
	}
	
	if(!(ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL)))
		return -ENOMEM;
	atbm_printk_warn("wdata->data.length = %d %d\n",wdata->data.length,sizeof(struct BestChannelSelect));
	if((ret = copy_from_user(ptr, wdata->data.pointer, wdata->data.length))){
		atbm_kfree(ptr);
		return -EINVAL;
	}
	BestCh = (struct BestChannelSelect *)ptr;
	
	atbm_printk_warn("start_channel = %d \n",BestCh->start_channel);
	atbm_printk_warn("end_channel = %d \n",BestCh->end_channel);
	atbm_printk_warn("SpecialFlag = %d \n",BestCh->SpecialFlag);
	
	if((BestCh->start_channel <= 0) || (BestCh->end_channel <= 0) || (BestCh->start_channel > BestCh->end_channel)){
		atbm_printk_warn("input parameters is not allows,start channel[%d] end channel[%d]  \n",
				BestCh->start_channel,BestCh->end_channel);
		ret = -EINVAL;
		goto exit;
	}
	
	//{
	
	
	if((ieee8011_channel_valid(&local->hw,36) == true) && (BestCh->SpecialFlag == 1)){
//		support_special = true;	
		
			all_n_channels = 18;
		
		atbm_printk_warn("support scan special! \n");
	}else{
//		support_special = false;	
		all_n_channels = 14;
		if(BestCh->end_channel > 14)
			BestCh->end_channel = 14;
		atbm_printk_warn("not support scan special! \n");
	}
	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		ret = -EOPNOTSUPP;
		goto exit;
	}
	memset(&req,0,sizeof(struct ieee80211_internal_channel_auto_select_req));

	if(atbm_internal_channel_auto_select(sdata,&req) == false){
		ret = -EOPNOTSUPP;
	}
	
	memset(&BestCh->scan_result,0,sizeof(Best_Channel_Scan_Result));
	memset(&results,0,sizeof(struct ieee80211_internal_channel_auto_select_results));
	results.version = 0;//use version 0

	/*
		start_channel
		end_channel
		2.4G & 5G
		if support 5G but not confine channel, default return 1~14 channel value , suggest_ch range 1~14
		
	*/
	
	start_channel = BestCh->start_channel;
	end_channel = BestCh->end_channel;
	
	//Determine channel validity
	
	for(i = 0; i < 18; i++){
		if(all_channels[i] == start_channel){
			j = i+1; //start channel valid
		}else if((all_channels[i] == end_channel) && (i > j)){
			k = i+1;//end_channel valid
		}
	}
	atbm_printk_warn("start_channel index[%d] end_index[%d] \n",j,k);
	// channel valid 
	if((j != 0) && (k != 0)){
		results.ignore_n_channels = all_n_channels - (k - j + 1);
		ignor_channels = (u8 *)atbm_kmalloc(results.ignore_n_channels,GFP_KERNEL);
		if(ignor_channels == NULL){
			ret = false;
			goto exit;
		}
		results.n_channels = k - j + 1;
		vaid_channels = (u8 *)atbm_kmalloc(results.n_channels,GFP_KERNEL);
		if(vaid_channels == NULL){
			ret = false;
			goto exit;
		}
		j = 0;
		k = 0;
		for(i = 0 ; i < all_n_channels ; i++){
			if((all_channels[i] < start_channel) || (all_channels[i] > end_channel)){
				ignor_channels[j++] = all_channels[i];
				
				atbm_printk_warn("ignor_channels[%d] : %d \n",j-1,ignor_channels[j-1]);
			}else{
				vaid_channels[k++] = all_channels[i];
				
				atbm_printk_warn("vaid_channels[%d] : %d \n",k-1,vaid_channels[k-1]);
			}
				
		}
		results.ignore_channels = ignor_channels;
		//results.ignore_n_channels = all_n_channels - (end_channel - start_channel + 1);
		results.channels = vaid_channels;
		//results.n_channels = end_channel - start_channel + 1;
		
	}else{
		start_channel = 1;
		end_channel = 14;
		if(all_n_channels == 18){
			ignor_channels = (u8 *)atbm_kmalloc(all_n_channels - 14,GFP_KERNEL);
			if(ignor_channels == NULL){
				ret = false;
				goto exit;
			}
		}
			
		
		vaid_channels = (u8 *)atbm_kmalloc(14,GFP_KERNEL);
		if(vaid_channels == NULL){
			ret = false;
			goto exit;
		}
		j = 0;
		k = 0;
		for(i = 0 ; i < all_n_channels ; i++){
			if((all_channels[i] < start_channel) || (all_channels[i] > end_channel)){
				if(all_n_channels == 18){
					ignor_channels[j++] = all_channels[i];
					
					atbm_printk_warn("ignor_channels[%d] : %d \n",j-1,ignor_channels[j-1]);
				}
			}else{
				vaid_channels[k++] = all_channels[i];
				
				atbm_printk_warn("vaid_channels[%d] : %d \n",k-1,vaid_channels[k-1]);
			}
				
		}
		results.ignore_channels = ignor_channels;
		results.ignore_n_channels = all_n_channels - 14;
		results.channels = vaid_channels;
		results.n_channels = 14;
	}

	


	
	
	atbm_printk_warn("[%s] start channel[%d] end channel[%d] results.ignore_n_channels[%d] results.n_channels[%d]\n",__func__,
											start_channel,end_channel,
											results.ignore_n_channels,results.n_channels);
	
	
	
	if(atbm_internal_channel_auto_select_results(sdata,&results) == false){
		ret = -EINVAL;
		goto exit;
	}
	
	

	for(i = 0;i<all_n_channels;i++){
		if(((i+1) >= start_channel) && ((i+1) <= end_channel)){
			BestCh->scan_result.channel_ap_num[i] = results.n_aps[i];
			BestCh->scan_result.busy_ratio[i] = results.busy_ratio[i];
			BestCh->scan_result.weight[i] = results.weight[i];
		}else{
			BestCh->scan_result.channel_ap_num[i] = 0;
			BestCh->scan_result.busy_ratio[i] = 0;
			BestCh->scan_result.weight[i] = 0;
		}
	
	}
	
	
	BestCh->scan_result.suggest_ch = results.susgest_channel;
	BestCh->SpecialFlag = 0;
	if(ieee8011_channel_valid(&local->hw,36) == true){
		BestCh->SpecialFlag = 1;
		atbm_printk_err("BestCh->SpecialFlag = 1 \n");
	}
	
	atbm_printk_err("auto_select channel %d\n",BestCh->scan_result.suggest_ch);
	//memcpy(&BestCh->scan_result, &scan_result, sizeof(scan_result));
//	if(wdata->data.length == sizeof(struct BestChannelSelect))
		if(copy_to_user(wdata->data.pointer, (char*)BestCh, sizeof(struct BestChannelSelect)) != 0)
			ret = -EINVAL;
//	}
		wdata->data.length = sizeof(struct BestChannelSelect);
exit:
	if(ignor_channels)
		atbm_kfree(ignor_channels);
	if(vaid_channels)
		atbm_kfree(vaid_channels);
	if(ptr)
		atbm_kfree(ptr);

	
	return ret;

}

#else

static int atbm_ioctl_best_ch_scan(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct BestChannelSelect{
		unsigned char start_channel;
		unsigned char end_channel;
		unsigned char SpecialFlag;
		Best_Channel_Scan_Result scan_result;
	};
	struct BestChannelSelect *BestCh = NULL;
	int ret = 0;
	
	unsigned char *ptr = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;

	if(!(ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL)))
		return -ENOMEM;
	atbm_printk_err("wdata->data.length = %d \n",wdata->data.length);
	if((ret = copy_from_user(ptr, wdata->data.pointer, wdata->data.length))){
		atbm_kfree(ptr);
		return -EINVAL;
	}

	if(memcmp(ptr, "start", 5) == 0)
		ret = atbm_ioctl_best_ch_start(dev, info, wrqu, extra);
	else if(memcmp(ptr, "result", 6) == 0)
		ret = atbm_ioctl_best_ch_scan_result(dev, info, wrqu, extra);
	else
		ret = -1;

	if(ret < 0)
		atbm_printk_err("atbm_ioctl_best_ch_scan(), error %s\n", ptr);
	
	atbm_kfree(ptr);
	
	return ret;
}
#endif

#ifdef SSTAR_FUNCTION

static int atbm_ioctl_get_SIGMSTAR_256BITSEFUSE(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	u8 efuseBuff[32] = {0};
	//u8 extraBuff[18] = {0};
	int ret = -EINVAL;
	int i;
//	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;

	//if(wrqu->data.length > 1){
	//	printk("command 'getsigmstarefuse' need not parameters\n");
	//	return ret;
	//}

	if ((ret = wsm_get_SIGMSTAR_256BITSEFUSE(hw_priv, &efuseBuff[0], sizeof(efuseBuff))) == 0){
		
		atbm_printk_wext("Get sigmstar efuse data:\n");
		for(i = 0; i < sizeof(efuseBuff); i++)
		{
			atbm_printk_wext("%02x ", efuseBuff[i]);
		}
		atbm_printk_wext("\n");
	}
	else{
		atbm_printk_err("read sigmstarefuse failed\n");
	}
	/*
	userdata_len = wdata->data.length;
	if(copy_to_user(wdata->data.pointer + userdata_len, efuseBuff, 32) != 0){
		ret = -EINVAL;
		atbm_printk_wext("copy to user failed.\n");
	}
	*/
	if(extra){	
		memcpy(extra,efuseBuff,32);	
		wrqu->data.length = 33;
	}
	
	return ret;	
}
static int atbm_ioctl_set_SIGMSTAR_256BITSEFUSE(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i;
	int ret = -EINVAL;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	u8 efuseBuff[32 +1];
	int strheadLen, trueLen;
	atbm_printk_wext("####### efuse\n");
	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}
	atbm_printk_err("length=%d,data=%s\n", wrqu->data.length, extra);
	strheadLen=strlen("setSigmstarEfuse,");
	trueLen =((wrqu->data.length - strheadLen) > 32) ? 32:(wrqu->data.length - strheadLen);
	atbm_printk_err("trueLen=%d,strheadLen=%d\n", trueLen, strheadLen);

	memset(efuseBuff, 0, sizeof(efuseBuff));
	for(i =0; i < trueLen; i++)
	{
		efuseBuff[i] = extra[strheadLen + i];
	}
	
	if ((ret = wsm_set_SIGMSTAR_256BITSEFUSE(hw_priv, &efuseBuff[0], 32)) == 0)
	{
		atbm_printk_wext("Set sigmstar efuse data:\n");
		for(i = 0; i < sizeof(efuseBuff); i++)
		{
			atbm_printk_wext("%02hhx ", efuseBuff[i]);
		}
		atbm_printk_wext("\n");
	}
	else{
		atbm_printk_err("write sigmstarefuse failed\n");
	}

	return ret;
}
#endif
#ifdef CONFIG_ATBM_IWPRIV_USELESS
static int atbm_ioctl_channel_test_start(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	u8 chTestStart = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;

	wsm_write_mib(hw_priv, WSM_MIB_ID_CHANNEL_TEST_START, &chTestStart, sizeof(u8), priv->if_id);
//	wsm_read_mib(hw_priv, WSM_MIB_ID_GET_CHANNEL_IDLE, NULL, sizeof(unsigned short), priv->if_id);

	return 0;
}
#endif
static int atbm_ioctl_get_channel_idle(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	
//	unsigned char *ptr = NULL;
	unsigned short idle = 0;

	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;

	if(sdata->vif.type != NL80211_IFTYPE_AP &&  sdata->vif.type != NL80211_IFTYPE_STATION){
		atbm_printk_err("atbm_ioctl_get_channel_idle() ## please run ap or sta mode\n");
		return -EINVAL;
	}
	
//	ptr = wdata->data.pointer;

	wsm_read_mib(hw_priv, WSM_MIB_ID_GET_CHANNEL_IDLE, &idle, sizeof(unsigned short), priv->if_id);

	atbm_printk_err("current_idle:%d\n", idle);
	//memcpy(extra, (char *)&idle, sizeof(unsigned short));
/*	
	if(copy_to_user(ptr + user_len, (char *)&idle, sizeof(unsigned short)) != 0)
		return -EINVAL;
*/
	if(extra){
		sprintf(extra,"\ncurrent_idle:%d\n", idle);
		wdata->data.length = strlen(extra);
	}
	
	return ret;
}
//#endif
static int atbm_ioctl_get_efuse(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i,num = 0,ret = -EINVAL;
	char *extra = NULL;
	char *type_val = NULL;
	char *pflag = NULL;
	int data_flag = 1;//default efuse data
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct efuse_headr efuse_data;

	memset(&efuse_data, 0, sizeof(efuse_data));
	memset(&hw_priv->efuse,0, sizeof(struct efuse_headr));

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}
	extra[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++){
		 if((extra[i] == ',') && (num == 0)){
			type_val= extra + i + 1;
			num++;
		}
		else if((extra[i] == ',') && (num == 1)){
			pflag = extra + i + 1;
			extra[i] = '\0';
			num++;
			data_flag = *pflag - '0';
			break;
		}
	}

	if ((ret = wsm_get_efuse_data(hw_priv, &efuse_data, sizeof(efuse_data))) == 0){	
		atbm_printk_init("Get efuse data is [%d,%d,%d,%d,%d,%d,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x]\n",
				efuse_data.version,efuse_data.dcxo_trim,efuse_data.delta_gain1,efuse_data.delta_gain2,efuse_data.delta_gain3,
				efuse_data.Tj_room,efuse_data.topref_ctrl_bias_res_trim,efuse_data.PowerSupplySel,efuse_data.mac[0],efuse_data.mac[1],
				efuse_data.mac[2],efuse_data.mac[3],efuse_data.mac[4],efuse_data.mac[5]);
		memcpy(&hw_priv->efuse, &efuse_data, sizeof(struct efuse_headr));
	}
	else{
		atbm_printk_err("read efuse failed\n");
	}

	//atbm_printk_always("type_val:%s,data_flag:%d\n", type_val, data_flag);
	if((data_flag == 0) && (!memcmp(type_val, "dcxo", 4)))
	{
		efuse_data.dcxo_trim = DCXOCodeRead(hw_priv);
		atbm_printk_always("[DCXO_TRIM_REG]efuse_data.dcxo_trim:%d\n", efuse_data.dcxo_trim);
	}
/*
	if(copy_to_user(wdata->data.pointer, &efuse_data, sizeof(efuse_data)) != 0){
		ret = -EINVAL;
		atbm_printk_wext("copy to user failed.\n");
	}
*/
	if(extra){
		memcpy(extra, &efuse_data,sizeof(efuse_data));
		wdata->data.length = sizeof(efuse_data);
	}

	atbm_kfree(extra);
	return ret;
}
static int atbm_ioctl_get_efuse_free_space(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{

	//int ret = -EINVAL;
	//char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	int efuse_remainbit = 0;
	efuse_remainbit = wsm_get_efuse_status(hw_priv, NULL);
	atbm_printk_err("efuse free space:[%d] bit \n", efuse_remainbit);
	
	if(ext){
		memcpy(ext, &efuse_remainbit,sizeof(efuse_remainbit));
		wdata->data.length = sizeof(efuse_remainbit);
	}

	return 0;
}
static int atbm_ioctl_get_efuse_first(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int ret = -EINVAL;
	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct efuse_headr efuse_data;

	memset(&efuse_data,0, sizeof(struct efuse_headr));
	if ((ret = wsm_get_efuse_first_data(hw_priv, (void *)&efuse_data, sizeof(struct efuse_headr))) == 0){	
		atbm_printk_always("efuse first data is [%d,%d,%d,%d,%d,%d,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x]\n",
				efuse_data.version,efuse_data.dcxo_trim,efuse_data.delta_gain1,efuse_data.delta_gain2,efuse_data.delta_gain3,
				efuse_data.Tj_room,efuse_data.topref_ctrl_bias_res_trim,efuse_data.PowerSupplySel,efuse_data.mac[0],efuse_data.mac[1],
				efuse_data.mac[2],efuse_data.mac[3],efuse_data.mac[4],efuse_data.mac[5]);
	}
	else{
		atbm_printk_err("read efuse failed\n");
	}
/*
	if(copy_to_user(wdata->data.pointer, &efuse_data, sizeof(efuse_data)) != 0){
		ret = -EINVAL;
		atbm_printk_wext("copy to user failed.\n");
	}
*/
	return ret;
}

static int atbm_ioctl_get_efuse_all_data(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int ret = -EINVAL,i = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	u8 buffer[128] = {0};

	memset(buffer,0, sizeof(buffer));
	if ((ret = wsm_get_efuse_all_data(hw_priv, (void *)&buffer, sizeof(buffer))) == 0){	
		for(i=0;i<109;i++)
			atbm_printk_err("%02x ",buffer[i]);
	}
	else{
		atbm_printk_err("read all efuse failed\n");
	}

	return ret;
}


static int atbm_ioctl_set_efuse(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = -EINVAL;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int strheadLen = 0;
	char *pRxData;
	int rxData;
	char cmd[50] = "";
	char writebuf[128] = "";
	int writeEfuseFlag = 0;//
	int efuse_remainbit = 0;
	int set_dcxo_flag = 0, set_deltagain_flag = 0;
	
	struct efuse_headr efuse_temp;

	memset(&efuse_temp,0,sizeof(struct efuse_headr));
	if(wsm_get_efuse_data(hw_priv, &efuse_temp, sizeof(efuse_temp)) != 0){
		atbm_printk_err("wsm_get_efuse_data failed!\n");
		return -EINVAL;

	}
	
	atbm_printk_wext("####### efuse\n");
	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}
	extra[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(extra[i] == ',')
		{
			strheadLen=i;
			memcpy(cmd, extra, i);
			break;
		}
	}

	atbm_printk_err("cmd:%s\n", cmd);
	
	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, extra, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(extra);
		return -EINVAL;
	}

	pRxData = &extra[strheadLen];
	atbm_printk_err("cmd:%s\n", pRxData);

	efuse_remainbit = wsm_get_efuse_status(hw_priv, NULL);
	atbm_printk_err("##before write efuse_remainbit:%d##\n", efuse_remainbit);

	if(memcmp(cmd, "setEfuse_dcxo", 13) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.dcxo_trim = rxData;
		if(rxData < 0 || rxData > 127){
			atbm_printk_err("ERR!!!  efuse_dcxo range is 0~127,now input value is [%d] \n",rxData);
			return -EINVAL;
			goto efuse_err;
		}
		CmdLine_GetHex(&pRxData, &writeEfuseFlag);
		set_dcxo_flag = 1;
		atbm_printk_err("set efuse data is dcxo[%d]\n",efuse_temp.dcxo_trim);
	}
	else if(memcmp(cmd, "setEfuse_deltagain", 18) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.delta_gain1 = rxData;
		if(rxData < 0 || rxData > 31){
			atbm_printk_err("ERR!!!  efuse delta_gain1 range is 0~31,now input value is [%d] \n",rxData);
			return -EINVAL;
			goto efuse_err;
		}
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.delta_gain2 = rxData;
		if(rxData < 0 || rxData > 31){
			atbm_printk_err("ERR!!!  efuse delta_gain2 range is 0~31,now input value is [%d] \n",rxData);
			return -EINVAL;
			goto efuse_err;
		}
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.delta_gain3 = rxData;
		if(rxData < 0 || rxData > 31){
			atbm_printk_err("ERR!!!  efuse delta_gain3 range is 0~31,now input value is [%d] \n",rxData);
			return -EINVAL;
			goto efuse_err;
		}

		CmdLine_GetHex(&pRxData, &writeEfuseFlag);
		set_deltagain_flag = 1;
		atbm_printk_err("set efuse data is delta_gain[%d,%d,%d]\n",
			efuse_temp.delta_gain1,efuse_temp.delta_gain2,efuse_temp.delta_gain3);
	}
	else if(memcmp(cmd, "setEfuse_tjroom", 15) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.Tj_room= rxData;
		if(rxData < 0 || rxData > 127){
			atbm_printk_err("ERR!!!  efuse_Tj_room range is 0~127,now input value is [%d] \n",rxData);
			return -EINVAL;
			goto efuse_err;
		}
		CmdLine_GetHex(&pRxData, &writeEfuseFlag);
		atbm_printk_err("set efuse data is Tj_room[%d]\n",efuse_temp.Tj_room);
	}
	else if(memcmp(cmd, "setEfuse_mac", 12) == 0)
	{
		CmdLine_GetHex(&pRxData, &rxData);
		efuse_temp.mac[0] = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxData);
		efuse_temp.mac[1] = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxData);
		efuse_temp.mac[2] = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxData);
		efuse_temp.mac[3] = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxData);
		efuse_temp.mac[4] = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxData);
		efuse_temp.mac[5] = rxData;
		writeEfuseFlag = 1;
		atbm_printk_err("set efuse data is mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",
					efuse_temp.mac[0],efuse_temp.mac[1],efuse_temp.mac[2],
					efuse_temp.mac[3],efuse_temp.mac[4],efuse_temp.mac[5]);
	}

	

	if(writeEfuseFlag)
	{

		if(set_dcxo_flag)
		{
			atbm_printk_err("set dcxo effect immediately && SET TO EFUSE\n");
			DCXOCodeWrite(hw_priv, efuse_temp.dcxo_trim);
		}
		if(set_deltagain_flag)
		{
			memset(writebuf, 0, sizeof(writebuf));
			sprintf(writebuf, "set_txpwr_and_dcxo,%d,%d,%d,%d ", efuse_temp.delta_gain1,
				efuse_temp.delta_gain2, efuse_temp.delta_gain3, efuse_temp.dcxo_trim);
			
			atbm_printk_init("cmd: %s\n", writebuf);
			ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, writebuf, strlen(writebuf), 0);
			if(ret < 0){
				atbm_printk_err("%s: write mib failed(%d). \n",__func__, ret);
			}	
		}
		
		ret = atbm_save_efuse(hw_priv, &efuse_temp);
		if (ret == 0){
			memcpy(&hw_priv->efuse,&efuse_temp,sizeof(struct efuse_headr));
			atbm_printk_err("setEfuse success \n");
		}else{
			atbm_printk_err("setEfuse failed [%d]\n", ret);
		}
		efuse_remainbit = wsm_get_efuse_status(hw_priv, NULL);
		atbm_printk_err("##after write efuse_remainbit:%d##\n", efuse_remainbit);
	}
	else
	{
		if(set_dcxo_flag)
		{
			atbm_printk_err("set dcxo effect immediately \n");
			DCXOCodeWrite(hw_priv, efuse_temp.dcxo_trim);
		}
		else
		{
			memset(writebuf, 0, sizeof(writebuf));
			sprintf(writebuf, "set_txpwr_and_dcxo,%d,%d,%d,%d ", efuse_temp.delta_gain1,
				efuse_temp.delta_gain2, efuse_temp.delta_gain3, efuse_temp.dcxo_trim);
			
			atbm_printk_init("cmd: %s\n", writebuf);
			ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, writebuf, strlen(writebuf), 0);
			if(ret < 0){
				atbm_printk_err("%s: write mib failed(%d). \n",__func__, ret);
			}	
		}
	}
efuse_err:
	atbm_kfree(extra);

	return ret;
}

static int atbm_ioctl_set_all_efuse(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = -EINVAL;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int strheadLen = 0;
	char *pRxData;
	int rxData;
	char cmd[50] = "";
	int efuse_remainbit = 0;
	//struct Tjroom_temperature_t tjroom_temp;
#if 1
	atbm_printk_wext("####### efuse\n");
	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}
	extra[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(extra[i] == ',')
		{
			strheadLen=i;
			memcpy(cmd, extra, i);
			break;
		}
	}

	atbm_printk_err("cmd:%s\n", cmd);
	
	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, extra, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(extra);
		return -EINVAL;
	}

	pRxData = &extra[strheadLen];
	atbm_printk_err("cmd:%s\n", pRxData);

	//if(memcmp(cmd, "setEfuse_dcxo", 13) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		hw_priv->efuse.dcxo_trim = rxData;
		if((rxData < 0) || (rxData > 127))
		{
			atbm_printk_err("invalid dcxo:%d\n", rxData);
			goto error;
		}
		atbm_printk_err("set efuse data is dcxo[%d]\n",hw_priv->efuse.dcxo_trim);
	}
	//else if(memcmp(cmd, "setEfuse_deltagain", 18) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		hw_priv->efuse.delta_gain1 = rxData;
		if((rxData < 0) || (rxData > 31))
		{
			atbm_printk_err("invalid delta_gain1:%d\n", rxData);
			goto error;
		}
		CmdLine_GetSignInteger(&pRxData, &rxData);
		hw_priv->efuse.delta_gain2 = rxData;
		if((rxData < 0) || (rxData > 31))
		{
			atbm_printk_err("invalid delta_gain2:%d\n", rxData);
			goto error;
		}
		CmdLine_GetSignInteger(&pRxData, &rxData);
		hw_priv->efuse.delta_gain3 = rxData;
		if((rxData < 0) || (rxData > 31))
		{
			atbm_printk_err("invalid delta_gain3:%d\n", rxData);
			goto error;
		}
		atbm_printk_err("set efuse data is delta_gain[%d,%d,%d]\n",
			hw_priv->efuse.delta_gain1,hw_priv->efuse.delta_gain2,hw_priv->efuse.delta_gain3);
	}
/*
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		hw_priv->efuse.Tj_room = rxData;
		if((rxData < 0) || (rxData > 127))
		{
			atbm_printk_err("invalid Tj_room:%d\n", rxData);
			goto error;
		}
		atbm_printk_err("set efuse data is Tj_room[%d]\n",hw_priv->efuse.dcxo_trim);
	}
*/
	//else if(memcmp(cmd, "setEfuse_mac", 12) == 0)
	{
		CmdLine_GetHex(&pRxData, &rxData);
		hw_priv->efuse.mac[0] = rxData;
		
		CmdLine_GetHex(&pRxData, &rxData);
		hw_priv->efuse.mac[1] = rxData;

		CmdLine_GetHex(&pRxData, &rxData);
		hw_priv->efuse.mac[2] = rxData;

		CmdLine_GetHex(&pRxData, &rxData);
		hw_priv->efuse.mac[3] = rxData;

		CmdLine_GetHex(&pRxData, &rxData);
		hw_priv->efuse.mac[4] = rxData;

		CmdLine_GetHex(&pRxData, &rxData);
		hw_priv->efuse.mac[5] = rxData;

		atbm_printk_err("set efuse data is mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",
					hw_priv->efuse.mac[0],hw_priv->efuse.mac[1],hw_priv->efuse.mac[2],
					hw_priv->efuse.mac[3],hw_priv->efuse.mac[4],hw_priv->efuse.mac[5]);
	}
#if 0
	memset(&tjroom_temp, 0, sizeof(tjroom_temp));
	if((ret = wsm_get_Tjroom_temperature(hw_priv, &tjroom_temp, sizeof(tjroom_temp))) == 0)
	{
		atbm_printk_always("Tjroom:%d, tempC:%d,stempC:%d\n", tjroom_temp.Tjroom,
			tjroom_temp.tempC,tjroom_temp.stempC);
	}
	else
	{
		atbm_printk_err("get Tjroom  failed\n");
	}
#endif
	hw_priv->efuse.version = 1;
	hw_priv->efuse.PowerSupplySel = 0;
	hw_priv->efuse.topref_ctrl_bias_res_trim = 0;
	
	atbm_printk_err("efuse data:[%d,%d,%d,%d,%d,%d,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x]\n",
		hw_priv->efuse.version,hw_priv->efuse.dcxo_trim,
		hw_priv->efuse.delta_gain1,hw_priv->efuse.delta_gain2,hw_priv->efuse.delta_gain3,
		hw_priv->efuse.Tj_room,hw_priv->efuse.PowerSupplySel,hw_priv->efuse.topref_ctrl_bias_res_trim,
		hw_priv->efuse.mac[0],hw_priv->efuse.mac[1],hw_priv->efuse.mac[2],
		hw_priv->efuse.mac[3],hw_priv->efuse.mac[4],hw_priv->efuse.mac[5]);

	//if(writeEfuseFlag)
	{
		ret = atbm_save_efuse(hw_priv, &hw_priv->efuse);
		if (ret == 0)
		{
			atbm_printk_err("setEfuse success \n");
		}else
		{
			atbm_printk_err("setEfuse failed [%d]\n", ret);
		}
		efuse_remainbit = wsm_get_efuse_status(hw_priv, NULL);
		atbm_printk_err("##after write efuse_remainbit:%d##\n", efuse_remainbit);
	}
#endif
error:	
	atbm_kfree(extra);

	return ret;
}


static int atbm_ioctl_set_all_efuse_V2(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = -EINVAL;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int strheadLen = 0;
	char *pRxData;
	int rxData;
	char cmd[50] = "";
	int efuse_remainbit = 0;
	
	atbm_printk_wext("Write all efuse\n");
	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}
	extra[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(extra[i] == ',')
		{
			strheadLen=i;
			memcpy(cmd, extra, i);
			break;
		}
	}

	atbm_printk_err("cmd:%s\n", cmd);
	
	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, extra, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(extra);
		return -EINVAL;
	}

	pRxData = &extra[strheadLen];
	atbm_printk_err("pRxData:%s\n", pRxData);

	//dcxo
	CmdLine_GetSignInteger(&pRxData, &rxData);
	hw_priv->efuse.dcxo_trim = rxData;
	if((rxData < 0) || (rxData > 127))
	{
		atbm_printk_err("invalid dcxo:%d\n", rxData);
		goto error;
	}
	atbm_printk_err("dcxo[%d]\n",hw_priv->efuse.dcxo_trim);
	//deltagain1
	CmdLine_GetSignInteger(&pRxData, &rxData);
	hw_priv->efuse.delta_gain1 = rxData;
	if((rxData < 0) || (rxData > 31))
	{
		atbm_printk_err("invalid delta_gain1:%d\n", rxData);
		goto error;
	}
	//deltagain2
	CmdLine_GetSignInteger(&pRxData, &rxData);
	hw_priv->efuse.delta_gain2 = rxData;
	if((rxData < 0) || (rxData > 31))
	{
		atbm_printk_err("invalid delta_gain2:%d\n", rxData);
		goto error;
	}
	//deltagain3
	CmdLine_GetSignInteger(&pRxData, &rxData);
	hw_priv->efuse.delta_gain3 = rxData;
	if((rxData < 0) || (rxData > 31))
	{
		atbm_printk_err("invalid delta_gain3:%d\n", rxData);
		goto error;
	}
	atbm_printk_err("delta_gain[%d,%d,%d]\n",
		hw_priv->efuse.delta_gain1,hw_priv->efuse.delta_gain2,hw_priv->efuse.delta_gain3);
	//Tj_room
	CmdLine_GetSignInteger(&pRxData, &rxData);
	hw_priv->efuse.Tj_room = rxData;
	if((rxData < 0) || (rxData > 127))
	{
		atbm_printk_err("invalid Tj_room:%d\n", rxData);
		goto error;
	}
	atbm_printk_err("Tj_room[%d]\n",hw_priv->efuse.dcxo_trim);

	//mac
	CmdLine_GetHex(&pRxData, &rxData);
	hw_priv->efuse.mac[0] = rxData;
	
	CmdLine_GetHex(&pRxData, &rxData);
	hw_priv->efuse.mac[1] = rxData;

	CmdLine_GetHex(&pRxData, &rxData);
	hw_priv->efuse.mac[2] = rxData;

	CmdLine_GetHex(&pRxData, &rxData);
	hw_priv->efuse.mac[3] = rxData;

	CmdLine_GetHex(&pRxData, &rxData);
	hw_priv->efuse.mac[4] = rxData;

	CmdLine_GetHex(&pRxData, &rxData);
	hw_priv->efuse.mac[5] = rxData;

	atbm_printk_err("mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",
				hw_priv->efuse.mac[0],hw_priv->efuse.mac[1],hw_priv->efuse.mac[2],
				hw_priv->efuse.mac[3],hw_priv->efuse.mac[4],hw_priv->efuse.mac[5]);


	hw_priv->efuse.version = 1;
	hw_priv->efuse.PowerSupplySel = 0;
	hw_priv->efuse.topref_ctrl_bias_res_trim = 0;
	
	atbm_printk_err("efuse data:[%d,%d,%d,%d,%d,%d,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x]\n",
		hw_priv->efuse.version,hw_priv->efuse.dcxo_trim,
		hw_priv->efuse.delta_gain1,hw_priv->efuse.delta_gain2,hw_priv->efuse.delta_gain3,
		hw_priv->efuse.Tj_room,hw_priv->efuse.PowerSupplySel,hw_priv->efuse.topref_ctrl_bias_res_trim,
		hw_priv->efuse.mac[0],hw_priv->efuse.mac[1],hw_priv->efuse.mac[2],
		hw_priv->efuse.mac[3],hw_priv->efuse.mac[4],hw_priv->efuse.mac[5]);

	
	ret = atbm_save_efuse(hw_priv, &hw_priv->efuse);
	if (ret == 0)
	{
		atbm_printk_err("setEfuse success \n");
	}else
	{
		atbm_printk_err("setEfuse failed [%d]\n", ret);
	}
	efuse_remainbit = wsm_get_efuse_status(hw_priv, NULL);
	atbm_printk_err("##after write efuse_remainbit:%d##\n", efuse_remainbit);

error:	
	atbm_kfree(extra);

	return ret;
}


static int atbm_ioctl_get_Tjroom(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = -EINVAL;
	char *pbuff = NULL;
	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct Tjroom_temperature_t tjroom_temp;

	if(!(pbuff = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}

	memset(&tjroom_temp, 0, sizeof(tjroom_temp));

	if((ret = wsm_get_Tjroom_temperature(hw_priv, &tjroom_temp, sizeof(tjroom_temp))) == 0)
	{
		atbm_printk_always("Tjroom:%d, tempC:%d,stempC:%d\n", tjroom_temp.Tjroom,
			tjroom_temp.tempC,tjroom_temp.stempC);
	}
	else
	{
		atbm_printk_err("get Tjroom  failed\n");
	}

	sprintf(pbuff, "Tjroom:%d, tempC:%d,stempC:%d\n", tjroom_temp.Tjroom,tjroom_temp.tempC,tjroom_temp.stempC);

	if(extra){	
		memcpy(extra, (char *)pbuff, strlen(pbuff));	
		wrqu->data.length = strlen(pbuff);
	}

	atbm_kfree(pbuff);
	
	return ret;
}

static int atbm_ioctl_set_calibrate_flag(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ret = -EINVAL;
	char *extra = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int strheadLen = 0;
	char *pRxData;
	int caliFlag;
	char cmd[50] = "";
	char writebuf[128] = "";

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		return -EINVAL;
	}
	extra[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(extra[i] == ',')
		{
			strheadLen=i;
			memcpy(cmd, extra, i);
			break;
		}
	}

	atbm_printk_err("cmd:%s\n", cmd);
	
	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, extra, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(extra);
		return -EINVAL;
	}

	pRxData = &extra[strheadLen];
	atbm_printk_err("cmd:%s\n", pRxData);

	CmdLine_GetSignInteger(&pRxData, &caliFlag);

	if((caliFlag != 0) && (caliFlag != 1))
	{
		atbm_printk_err("Invalid parameter:%s\n", pRxData);
		return -EINVAL;
	}

	if(caliFlag == 1)
	{
		memset(writebuf, 0, sizeof(writebuf));
		sprintf(writebuf, "set_cali_flag,%d ", caliFlag);		
		atbm_printk_init("cmd: %s\n", writebuf);	
	}
	else
	{
		memset(writebuf, 0, sizeof(writebuf));
		sprintf(writebuf, "set_cali_flag,%d ", caliFlag);			
		atbm_printk_init("cmd: %s\n", writebuf);			
	}
	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, writebuf, strlen(writebuf), 0);
	if(ret < 0){
		atbm_printk_err("%s: write mib failed(%d). \n",__func__, ret);
	}
			
	atbm_kfree(extra);

	return ret;
}


#ifdef CONFIG_ATBM_IWPRIV_USELESS
static int atbm_ioctl_freqoffset(struct net_device *dev, struct iw_request_info *info, union iwreq_data  *wrqu, char *extra)
{
	int i = 0;	
	int ret = 0;
	int iResult=0;
	
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	//struct atbm_vif *vif;
	struct efuse_headr efuse_d,efuse_bak;
	u32 dcxo;
	int freqErrorHz;
	int ucWriteEfuseFlag = 0;
	int channel = 0;
	char *SavaEfuse_p = NULL;
	
	u8 buff[512];
	struct rxstatus_signed rxs_s;

	memset(&rxs_s,0,sizeof(struct rxstatus));
	memset(&efuse_d,0,sizeof(struct efuse_headr));
	memset(&efuse_bak,0,sizeof(struct efuse_headr));

	if(wrqu->data.length <= 3){
		atbm_printk_err("need to input parameters\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 start_rx 1,0\n");
		return -EINVAL;
	}

	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL)))
		return -EINVAL;

	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length)) != 0){
		atbm_kfree(extra);
		return -EINVAL;
	}

	for(i=0;extra[i] != ',';i++){
		if(extra[i] == ','){
			break;
		}
		channel = channel * 10 +(extra[i] - 0x30);
	}

	for(i=0;i<wrqu->data.length;i++){
			if(extra[i] == ','){
				SavaEfuse_p = extra +i + 1;
				break;
			}	
		}

	if((NULL == SavaEfuse_p) || (SavaEfuse_p[0] == '\0')){
		atbm_printk_err("invalid SavaEfuse_p\n");
		atbm_printk_err("ucWriteEfuseFlag value: 1:save efuse,0:not save efuse\n");
		atbm_kfree(extra);
		return -EINVAL;
	}

	for(i=0;SavaEfuse_p[i] != '\0';i++){
		if(1 == i){
		atbm_printk_err("invalid SavaEfuse_p1\n");
		atbm_printk_err("ucWriteEfuseFlag value: 1:save efuse,0:not save efuse\n");
		atbm_kfree(extra);
			return 	-EINVAL;
		}
		ucWriteEfuseFlag = ucWriteEfuseFlag * 10 + (SavaEfuse_p[i] - 0x30);
	}

	atbm_printk_wext("channel:%d ucWriteEfuseFlag:%d\n",channel, ucWriteEfuseFlag);

	
	if((ucWriteEfuseFlag != 0) && (ucWriteEfuseFlag != 1)){
		atbm_printk_err("invalid WriteEfuseFlag\n");
		atbm_kfree(extra);
		return -EINVAL;
	}
	
	if(channel <= 0 || channel > 14){
			atbm_printk_err("invalid channel!\n");
			atbm_kfree(extra);
			return -EINVAL;
		}

	for(i=0;i<wrqu->data.length;i++){
		if(extra[i] == ',')
			extra[i] =' ';
	}
		
	if(Test_FreqOffset(hw_priv,&dcxo, &freqErrorHz, &rxs_s, channel)){
		atbm_printk_err("Test_FreqOffset Error\n");
		iResult = -1;
		goto FEEQ_ERR;
	}
	//tmp = DCXOCodeRead(hw_priv);printk("tmp %d\n"tmp);	
	if(ucWriteEfuseFlag)
	{
		atbm_printk_wext("ucWriteEfuseFlag :%d\n",ucWriteEfuseFlag);
		wsm_get_efuse_data(hw_priv,(void *)&efuse_d,sizeof(struct efuse_headr));

		if(efuse_d.version == 0)
		{
			iResult = -3;
			goto FEEQ_ERR;
		}
		efuse_d.dcxo_trim = dcxo;
		/*
		*LMC_STATUS_CODE__EFUSE_VERSION_CHANGE	failed because efuse version change  
		*LMC_STATUS_CODE__EFUSE_FIRST_WRITE, 		failed because efuse by first write   
		*LMC_STATUS_CODE__EFUSE_PARSE_FAILED,		failed because efuse data wrong, cannot be parase
		*LMC_STATUS_CODE__EFUSE_FULL,				failed because efuse have be writen full
		*/
		ret = wsm_efuse_change_data_cmd(hw_priv, &efuse_d,0);
		if (ret == LMC_STATUS_CODE__EFUSE_FIRST_WRITE)
		{
			iResult = -3;
		}else if (ret == LMC_STATUS_CODE__EFUSE_PARSE_FAILED)
		{
			iResult = -4;
		}else if (ret == LMC_STATUS_CODE__EFUSE_FULL)
		{
			iResult = -5;
		}else if (ret == LMC_STATUS_CODE__EFUSE_VERSION_CHANGE)
		{
			iResult = -6;
		}else
		{
			iResult = 0;
		}

		frame_hexdump("efuse_d", (u8 *)&efuse_d, sizeof(struct efuse_headr));
		wsm_get_efuse_data(hw_priv,(void *)&efuse_bak, sizeof(struct efuse_headr));
		frame_hexdump("efuse_bak", (u8 *)&efuse_bak, sizeof(struct efuse_headr));
		
		if(memcmp((void *)&efuse_bak,(void *)&efuse_d, sizeof(struct efuse_headr)) !=0)
		{
			iResult = -2;
		}else
		{
			iResult = 0;
		}
		
	}

	
FEEQ_ERR:	
	
	sprintf(buff, "cfo:%d,evm:%d,gainImb:%d, phaseImb:%d,dcxo:%d,result:%d (0:OK; -1:FreqOffset Error; -2:efuse hard error;"
		" -3:efuse no written; -4:efuse anaysis failed; -5:efuse full; -6:efuse version change)",
	rxs_s.Cfo,
	rxs_s.evm,
	rxs_s.GainImb,
	rxs_s.PhaseImb,
	dcxo,
	iResult
	);

	if((ret = copy_to_user(wrqu->data.pointer, buff, strlen(buff))) != 0){
		atbm_kfree(extra);
		return -EINVAL;
	}
	atbm_kfree(extra);
	return ret;
}
#endif

static int atbm_ioctl_send_singleTone(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ii = 0;
	int ret = -EINVAL;
	int channel = 0;
	int ucDbgPrintOpenFlag = 1;
	char *extra = NULL;
	char *ptr = NULL;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif = NULL;

	if(ETF_bStartTx || ETF_bStartRx){
		if(ETF_bStartTx){
			atbm_ioctl_stop_tx(dev,info,wrqu,ext);	
		}else{
			atbm_printk_err("Error! already send_singleTone, please stop_rx first!\n");
			return 0;
		}
	}
	
	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		ret = -EINVAL;
		goto exit;
	}
	extra[wrqu->data.length] = 0;

	atbm_printk_debug("atbm_ioctl_send_singleTone:%d,%d\n",strlen(extra), wrqu->data.length);

	atbm_printk_debug("atbm_ioctl_send_singleTone:%s\n",extra);

	if(wrqu->data.length < strlen("singletone,7")){
		atbm_printk_err("e.g: ./iwpriv wlan0 common singletone,<channel>\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 common singletone,7\n");
		ret = -EINVAL;
		goto exit;
	}


	for(ii = 0;ii<wrqu->data.length;ii++){
		if(extra[ii] == ',')
		{
			ptr = &extra[ii+1];

			break;
		}
	}

	for(ii = 0;ii<strlen(ptr);ii++)
	{
		channel = (channel * 10) + (ptr[ii] - 0x30);
	}

	if((channel <= 0) || (channel > 14))
	{
		atbm_printk_always("[ERROR]invalid channel:%d\n",channel);
		ret = -1;
		goto exit;
	}

	hw_priv->etf_channel = channel;
	hw_priv->etf_channel_type = 0;
	hw_priv->etf_rate = 4;
	hw_priv->etf_len = 1000; 
	hw_priv->etf_greedfiled = 0;

	atbm_printk_always("channel:%d\n",channel);
	
	atbm_for_each_vif(hw_priv,vif,i){
		if((vif != NULL)){			
			atbm_printk_wext("####### send singleTone #######\n");
			
			down(&hw_priv->scan.lock);
			
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
				&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
			
			mutex_lock(&hw_priv->conf_mutex);
			ETF_bStartTx = 1;
			wsm_start_tx(hw_priv, vif->vif);
			mutex_unlock(&hw_priv->conf_mutex);
			break;
		}
	}
exit:
	if(extra)
		atbm_kfree(extra);
	return ret;
}

static int atbm_ioctl_set_duty_ratio(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	int i = 0;
	int ii = 0;
	int ret = -EINVAL;
	int duty_ratio = 0;
	char *extra = NULL;
	char *ptr = NULL;
	int flag = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *vif = NULL;


	if(!(extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(extra);
		ret = -EINVAL;
		goto exit;
	}
	extra[wrqu->data.length] = 0;

	atbm_printk_always("atbm_ioctl_set_duty_ratio:%s\n",extra);

	if(wrqu->data.length < strlen("duty_ratio,")){
		atbm_printk_err("e.g: ./iwpriv wlan0 common duty_ratio,<duty_ratio_value>\n");
		atbm_printk_err("e.g: ./iwpriv wlan0 common duty_ratio,0.1\n");
		atbm_kfree(extra);
		ret = -EINVAL;
		goto exit;
	}


	for(ii = 0;ii<wrqu->data.length;ii++){
		if(extra[ii] == ',')
		{
			ptr = &extra[ii+1];

			break;
		}
	}
	atbm_printk_always(" ptr:%s\n",ptr);

	for(ii = 0;ii<strlen(ptr);ii++)
	{
		if(ptr[ii] == ','){
			break;
		}
		if(ptr[ii] == '.'){
			flag = 1;
			continue;
		}	
		duty_ratio = duty_ratio* 10 +(ptr[ii] - 0x30);
	}

	if(flag == 0)
		duty_ratio = duty_ratio * 10;

	if((duty_ratio < 0) || (duty_ratio > 10))
	{
		atbm_printk_always("[ERROR]invalid duty_ratio:%d\n",duty_ratio);
		ret = -1;
		goto exit;
	}

	atbm_printk_always("duty_ratio:%d\n",duty_ratio);
	
	atbm_for_each_vif(hw_priv,vif,i){
		if((vif != NULL)){			
			wsm_write_mib(hw_priv, WSM_MIB_ID_SET_DUTY_RATIO,
				&duty_ratio, sizeof(duty_ratio), vif->if_id);
			break;
		}
	}
exit:
	if(extra)
		atbm_kfree(extra);
	return ret;
}

#ifdef CONFIG_ATBM_SUPPORT_AP_CONFIG
static int atbm_ioctl_set_ap_conf(struct net_device *dev, struct iw_request_info *info, 
										   union iwreq_data *wrqu, char *ext)
{
	struct ieee80211_internal_ap_conf conf_req;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	char *extra = NULL;
	const char* pos;
	const char* pos_end;
	int ret = 0;
	int len = 0;
	int channel = 0;
	int i;
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}
	
	extra = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL);

	if(extra == NULL){
		ret =  -ENOMEM;
		goto exit;
	}

	if((ret = copy_from_user(extra, wrqu->data.pointer, wrqu->data.length))){
		return -EINVAL;
		goto exit;
	}
	
	extra[wrqu->data.length] = 0;

	for(i = 0;i<wrqu->data.length;i++){
		if(extra[i] == ',')
			extra[i] = ATBM_SPACE;
	}
	
	atbm_printk_debug("%s:%s %d\n",__func__,extra,wrqu->data.length);
	pos = atbm_skip_space(extra,wrqu->data.length);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("ap_conf");

	pos = atbm_skip_space(pos,wrqu->data.length-(pos-extra));

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}
	len = wrqu->data.length - (pos - extra);

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}
	
	pos_end = memchr(pos,ATBM_TAIL,len);
	if(pos_end != NULL)
		len = pos_end - pos;

	if(len>2){
		ret = -EINVAL;
		goto exit;
	}

	if(atbm_accsii_to_int(pos,len,&channel) == false){		
		ret = -EINVAL;
		goto exit;
	}

	if(channel && (ieee8011_channel_valid(&sdata->local->hw,channel) == false)){
		ret = -EINVAL;
		goto exit;
	}
	
	memset(&conf_req,0,sizeof(struct ieee80211_internal_ap_conf));
	conf_req.channel = (u8)channel;

	if(atbm_internal_update_ap_conf(sdata,&conf_req,conf_req.channel == 0?true:false) == false)
		ret = -EINVAL;
	
exit:
	if(extra)
		atbm_kfree(extra);

	return ret;
}
#endif
#ifdef CONFIG_ATBM_MONITOR_SPECIAL_MAC
static int atbm_ioctl_rx_monitor_mac(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_internal_mac_monitor mac_moniter;
	char *ptr = NULL;
	char const *pos = NULL;
	char const *pos_next = NULL;
	char const *pos_end = NULL;
	int ret = 0;
	int i   = 0;
	int len = 0;
	int enable = 0;
	int index = -1;

	if(ieee80211_get_channel_mode(local,NULL) != CHAN_MODE_FIXED){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret =  -ENOMEM;
		goto exit;
	}
	
	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(ptr[i] == ',')
			ptr[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("monitor_mac");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length+1 - (pos - ptr);

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	/*
	*parase enable
	*/
	pos_next = memchr(pos,ATBM_SPACE,len);

	if(pos_next == NULL)
		pos_next = memchr(pos,ATBM_TAIL,len);
	
	if(pos_next - pos > 1){
		ret = -EINVAL;
		goto exit;
	}
	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos;
	
	memset(&mac_moniter,0,sizeof(struct ieee80211_internal_mac_monitor));
	
	if(atbm_accsii_to_int(pos,pos_next - pos,&enable) == false){		
		ret = -EINVAL;
		goto exit;
	}

	if(enable)
		mac_moniter.flags |= IEEE80211_INTERNAL_MAC_MONITOR_START;
	else 
		mac_moniter.flags |= IEEE80211_INTERNAL_MAC_MONITOR_STOP;

	pos_next++;
	len -= (pos_next-pos);
	pos = pos_next;

	/*
	*parase index
	*/

	pos_next = memchr(pos,ATBM_SPACE,len);

	if(pos_next == NULL)
		pos_next = memchr(pos,ATBM_TAIL,len);

	if(pos_next == NULL)
		pos_next = pos+1;

	if(pos_next - pos > 1){
		ret = -EINVAL;
		goto exit;
	}

	if(atbm_accsii_to_int(pos,pos_next - pos,&index) == false){		
		ret = -EINVAL;
		goto exit;
	}

	if((index != 0)&&(index != 1)){
		ret = -EINVAL;
		goto exit;
	}

	pos_next++;
	len -= (pos_next-pos);
	pos = pos_next;
	mac_moniter.index = index;
	
	if(enable){
		u8 mac_len = 0;
		u8 hex;
		u8 mac_begin = 0;
		i = 0;
		/*
		*00:11:22:33:44:55
		*/
		if(len != 17){
			ret = -EINVAL;
			goto exit;
		}
		
		for(i=0;i<17;i++){
		
			if(pos[i] == ':'){
				mac_len++;
				mac_begin = 0;
				continue;
			}

			if(mac_len>=6){
				ret = -EINVAL;
				goto exit;
			}

			if(mac_begin>1){
				ret = -EINVAL;
				goto exit;
			}
			if (atbm_accsii_to_hex(pos[i],&hex) == false){
				goto exit;
			}
			mac_moniter.mac[mac_len] *= 16;
			mac_moniter.mac[mac_len] += hex;
			mac_begin++;
		}
	}else if(atbm_skip_space(pos,len) != NULL){
		ret = -EINVAL;
		goto exit;
	}
	
	if(atbm_internal_mac_monitor(&local->hw,&mac_moniter) == false){
		ret = -EINVAL;
		goto exit;
	}
exit:
	if(ptr)
		atbm_kfree(ptr);

	return ret;
}
static int atbm_ioctl_rx_monitor_mac_status(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_internal_mac_monitor mac_moniter;
	int ret = 0;
	char *results = NULL;
	int i = 0;
	int copy_len = 0;
	int total_len = 0;
	
	memset(&mac_moniter,0,sizeof(struct ieee80211_internal_mac_monitor));

	mac_moniter.flags = IEEE80211_INTERNAL_MAC_MONITOR_RESULTS;
	
	results = (char *)atbm_kzalloc(1024, GFP_KERNEL);

	if(results == NULL){
		ret =  -ENOMEM;
		goto exit;
	}
	
	if(atbm_internal_mac_monitor(&local->hw,&mac_moniter) == false){
		ret = -EINVAL;
		goto exit;
	}

	copy_len = scnprintf(results+total_len,1024-total_len,"mac monitor status --->\n");

	total_len += copy_len;
	for(i = 0;i < IEEE80211_INTERNAL_MAC_MONITOR_RESULTS;i++){
		
		if(mac_moniter.reults[i].used == 0)
			break;
		copy_len = scnprintf(results+total_len,1024-total_len,
			  "index=[%d],enable[%d],forcestop[%d],mac=[%pM],found=[%d],rssi[%d],deltime[%d]ms\n",
			  mac_moniter.reults[i].index,
			  mac_moniter.reults[i].enabled,
			  mac_moniter.reults[i].forcestop,
			  mac_moniter.reults[i].mac,
			  mac_moniter.reults[i].found,
			  mac_moniter.reults[i].rssi >= 128 ? mac_moniter.reults[i].rssi-256:mac_moniter.reults[i].rssi,
			  mac_moniter.reults[i].delta_time);
		if(copy_len > 0)
			total_len+=copy_len;
		else
			break;
	}

	if(extra){
		memcpy(extra,results,total_len);	
		wrqu->data.length = total_len + 1;
	}
exit:
	if(results)
		atbm_kfree(results);
	return ret;
}
#endif

#ifdef CONFIG_IEEE80211_SPECIAL_FILTER
static int atbm_ioctl_rx_filter_frame(struct net_device *dev, 
			struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_special_filter filter;
	char *ptr = NULL;
	char const *pos = NULL;
	int ret = 0;
	int len = 0;
	int i = 0;
	char type = 0;
	char hex = 0;
	char n_params = 0;
	
	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret =  -ENOMEM;
		goto exit;
	}

	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = ATBM_SPACE;
	
	for(i = 0;i<wrqu->data.length;i++){
		if((ptr[i] == ATBM_LINEF) || 
		   (ptr[i] == ATBM_ENTER) || 
		   (ptr[i] == ATBM_TAIL) ||
		   (ptr[i] == ',') || (ptr[i] == 0)){
		   if(ptr[i] == ',')
		   		n_params ++;
		   ptr[i] = ATBM_SPACE;
		}
	}

	if(n_params != 1){
		atbm_printk_debug("%s:n_params(%d)\n",__func__,n_params);
		ret = -EINVAL;
		goto exit;
	}
	
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		atbm_printk_debug("%s:pos == NULL\n",__func__);
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("filter_frame");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		atbm_printk_debug("%s:pos == NULL2\n",__func__);
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - ptr);

	if(len < 2){
		atbm_printk_debug("%s:len(%d)\n",__func__,len);
		ret = -EINVAL;
		goto exit;
	}

	for(i=0;i<2;i++){
		if (atbm_accsii_to_hex(pos[i],&hex) == false){
			goto exit;
		}
		type *= 16;
		type += hex;
	}

	pos += 2;
	len -= 2;

	if(atbm_skip_space(pos,len)){
		atbm_printk_debug("%s:pos is not null\n",__func__);
		ret = -EINVAL;
		goto exit;
	}
	memset(&filter,0,sizeof(struct ieee80211_special_filter));
	filter.filter_action = type;
	filter.flags = SPECIAL_F_FLAGS_FRAME_TYPE;
	atbm_printk_debug("%s:action(%x)\n",__func__,filter.filter_action);
	ieee80211_special_filter_register(sdata,&filter);
exit:
	if(ptr)
		atbm_kfree(ptr);	
	return ret;
}
static int atbm_ioctl_rx_filter_ie(struct net_device *dev, 
			struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_special_filter filter;
	char *ptr = NULL;
	char const *pos = NULL;
	char const *pos_next = NULL;
	int ret = 0;
	int len = 0;
	int i = 0;
	char n_params = 0;
	int ie_oui[4] = {0,0,0,0};
	
	
	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret = -ENOMEM;
		goto exit;
	}

	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = ATBM_SPACE;
	
	for(i = 0;i<wrqu->data.length;i++){
		if((ptr[i] == ATBM_LINEF) || 
		   (ptr[i] == ATBM_ENTER) || 
		   (ptr[i] == ATBM_TAIL) ||
		   (ptr[i] == ',')||(ptr[i] == 0)){
		   if(ptr[i] == ',')
		   		n_params ++;
		   ptr[i] = ATBM_SPACE;
		}
	}

	if((n_params != 1)&&(n_params != 4)){
		atbm_printk_debug("%s:1\n",__func__);
		ret = -EINVAL;
		goto exit;
	}
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		atbm_printk_debug("%s:2\n",__func__);
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("filter_ie");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		atbm_printk_debug("%s:3\n",__func__);
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - ptr);

	if(len < 2){	
		atbm_printk_debug("%s:5\n",__func__);
		ret = -EINVAL;
		goto exit;
	}

	for(i = 0;i<n_params;i++){

		if( len <= 0 ){
			atbm_printk_debug("%s:6 %d\n",__func__,i);
			ret = -EINVAL;
			goto exit;
		}
				
		pos_next = memchr(pos,ATBM_SPACE,len);
		if(pos_next == NULL){
			atbm_printk_debug("%s:7 %d\n",__func__,i);
			ret = -EINVAL;
			goto exit;
		}			
		
		if((pos_next - pos > 3) || (pos_next - pos < 1)){
			atbm_printk_debug("%s:8 %d\n",__func__,i);
			ret = -EINVAL;
			goto exit;
		}
		atbm_accsii_to_int(pos,pos_next-pos,&ie_oui[i]);
		len -= (pos_next + 1 - pos);
		pos = pos_next + 1;
		
	}

	memset(&filter,0,sizeof(struct ieee80211_special_filter));

	filter.filter_action = ie_oui[0];
	filter.flags = SPECIAL_F_FLAGS_FRAME_IE;
	
	if(n_params > 1){
		filter.oui[0] = ie_oui[1];
		filter.oui[1] = ie_oui[2];
		filter.oui[2] = ie_oui[3];
		filter.flags |= SPECIAL_F_FLAGS_FRAME_OUI;
	}
	atbm_printk_debug("%s:ie[%d],oui[%d:%d:%d]\n",__func__,filter.filter_action,filter.oui[0],filter.oui[1],filter.oui[2]);
	ieee80211_special_filter_register(sdata,&filter);
exit:
	if(ptr)
		atbm_kfree(ptr);	
	return ret;

}
static int atbm_ioctl_rx_filter_clear(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	const char *pos;
	char *ptr = NULL;
	int ret = 0;
	int i = 0;
	u8 n_params = 0;
	
	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret = -ENOMEM;
		goto exit;
	}

	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = ATBM_SPACE;
	
	for(i = 0;i<wrqu->data.length;i++){
		if((ptr[i] == ATBM_LINEF) || 
		   (ptr[i] == ATBM_ENTER) || 
		   (ptr[i] == ATBM_TAIL) ||
		   (ptr[i] == ',')||(ptr[i] == 0)){
		   if(ptr[i] == ',')
		   		n_params ++;
		   ptr[i] = ATBM_SPACE;
		}
	}

	if(n_params > 0){
		atbm_printk_debug("%s:n_params (%d)\n",__func__,n_params);
		ret = -EINVAL;
		goto exit;
	}

	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		atbm_printk_debug("%s:2\n",__func__);
		ret = -EINVAL;
		goto exit;
	}
	
	pos = pos+strlen("filter_clear");
	
	if(atbm_skip_space(pos,wrqu->data.length+1 - (pos-ptr))){
		atbm_printk_debug("%s:ptr err\n",__func__);
		ret = -EINVAL;
		goto exit;
	}
	
	ieee80211_special_filter_clear(sdata);
exit:
	if(ptr){
		atbm_kfree(ptr);
	}
	return ret;
}
static int atbm_ioctl_rx_filter_show(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_special_filter_table *tables = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	const char *pos;
	char *ptr = NULL;
	int ret = 0;
	int i = 0;
	u8 n_params = 0;
	char *results = NULL;
	int copy_len = 0;
	int total_len = 0;

	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1,GFP_KERNEL);
	
	if(!ptr){
		ret = -ENOMEM;
		goto exit;
	}
	
	tables = atbm_kzalloc(sizeof(struct ieee80211_special_filter_table),GFP_KERNEL);
	
	if(tables == NULL){
		ret = -ENOMEM;
		goto exit;
	}
	/*
	*max is 513
	*/
	results = atbm_kzalloc(512,GFP_KERNEL);
	
	if(results == NULL){
		ret = -ENOMEM;
		goto exit;
	}
	
	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = ATBM_SPACE;
	
	for(i = 0;i<wrqu->data.length;i++){
		if((ptr[i] == ATBM_LINEF) || 
		   (ptr[i] == ATBM_ENTER) || 
		   (ptr[i] == ATBM_TAIL) ||
		   (ptr[i] == ',')||(ptr[i] == 0)){
		   if(ptr[i] == ',')
		   		n_params ++;
		   ptr[i] = ATBM_SPACE;
		}
	}

	if(n_params > 0){
		atbm_printk_debug("%s:n_params (%d)\n",__func__,n_params);
		ret = -EINVAL;
		goto exit;
	}

	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		atbm_printk_debug("%s:2\n",__func__);
		ret = -EINVAL;
		goto exit;
	}
	
	pos = pos + strlen("filter_show");
	
	if(atbm_skip_space(pos,wrqu->data.length+1 - (pos-ptr))){
		atbm_printk_debug("%s:ptr err (%s)(%d)\n",__func__,pos,wrqu->data.length+1 - (pos-ptr));
		ret = -EINVAL;
		goto exit;
	}

	ieee80211_special_filter_request(sdata,tables);

	copy_len = scnprintf(results+total_len,512-total_len,"filter table --->\n");
	total_len += copy_len;
	
	for(i = 0;i < tables->n_filters;i++){

		if((tables->table[i].flags & IEEE80211_SPECIAL_FILTER_MASK) == SPECIAL_F_FLAGS_FRAME_TYPE)
			copy_len = scnprintf(results+total_len,512-total_len,"filter[%d]: frame [%x]\n",i,tables->table[i].filter_action);
		else if((tables->table[i].flags & IEEE80211_SPECIAL_FILTER_MASK) == SPECIAL_F_FLAGS_FRAME_IE)
			copy_len = scnprintf(results+total_len,512-total_len,"filter[%d]: ie[%d]\n",i,tables->table[i].filter_action);
		else if((tables->table[i].flags & IEEE80211_SPECIAL_FILTER_MASK) == (SPECIAL_F_FLAGS_FRAME_IE | SPECIAL_F_FLAGS_FRAME_OUI)){
			copy_len = scnprintf(results+total_len,512-total_len,"filter[%d]: ie[%d] oui[%d:%d:%d]\n",i,tables->table[i].filter_action,
				tables->table[i].oui[0],tables->table[i].oui[1],tables->table[i].oui[2]);
		}else {
			copy_len = scnprintf(results+total_len,512-total_len,"filter[%d]: unkown\n",i);
		}
		if(copy_len > 0)
			total_len+=copy_len;
		else
			break;
	}
	
	if(extra){
		memcpy(extra,results,total_len);	
		wrqu->data.length = total_len + 1;
	}
	
exit:
	if(ptr)
		atbm_kfree(ptr);
	if(tables)
		atbm_kfree(tables);
	if(results)
		atbm_kfree(results);
	return ret;
}
#endif
#ifdef HIDDEN_SSID
//extern int atbm_upload_beacon_private(struct atbm_vif *priv);
static int atbm_ioctl_set_hidden_ssid(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0,i=0,strheadLen=0;
//	int len = 0;
	char *ptr = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	//struct ieee80211_local *local = sdata->local;
	//struct atbm_common *hw_priv=local->hw.priv;
	struct atbm_vif *priv = (struct atbm_vif *)sdata->vif.drv_priv;


	atbm_printk_wext("atbm_ioctl_set_hidden_ssid()\n\n");

	if(sdata->vif.type != NL80211_IFTYPE_STATION){

		if(!(ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL)))
			return -ENOMEM;
		if((ret = copy_from_user(ptr, wdata->data.pointer, wdata->data.length))){
			atbm_kfree(ptr);
			return -EINVAL;
		}
		ptr[wdata->data.length] = 0;
//		len = wdata->data.length-1;
		for(i=0;i<wdata->data.length;i++)
		{
			if(ptr[i] == ',')
			{
				strheadLen=i+1;
				break;
			}
		}
		atbm_printk_err("strheadLen = %d,ptr[strheadLen] = %d wdata->data.length = %d \n",strheadLen,ptr[strheadLen],wdata->data.length);
		if( strheadLen != 0 ){
			if(ptr[strheadLen] == 0x30)
				priv->hidden_ssid = 0;
			else
				priv->hidden_ssid = 1;
		}else{
			atbm_printk_err("set hide ssid paramters error \n");
			atbm_kfree(ptr);
			ret = -1;
			goto Error;
		}

		ret = atbm_upload_beacon_private(priv);
		if(ret < 0){
			atbm_printk_err("error, upload beacon private failed %d\n", ret);
			atbm_kfree(ptr);
			goto Error;
		}

		atbm_kfree(ptr);



	}else{
		atbm_printk_err("warning, only AP mode support hidden ssid func, type(%d) \n", sdata->vif.type);
	}

Error:
	return ret;
}
#endif
static int atbm_ioctl_associate_sta_status(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_local *local = sdata->local;	
	struct ieee80211_channel_state *chan_state = ieee80211_get_channel_state(local, sdata);
	struct sta_info *sta;
	const char *pos;
	char *ptr = NULL;
	int ret = 0;
	int i = 0;
	u8 n_params = 0;
	char *results = NULL;
	int copy_len = 0;
	int total_len = 0;

	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	if(chan_state->oper_channel == NULL){
		ret =  -ENETDOWN;
		goto exit;
	}
	ptr = (char *)atbm_kzalloc(wdata->data.length+1,GFP_KERNEL);
	
	if(!ptr){
		ret = -ENOMEM;
		goto exit;
	}
	/*
	*max is 513
	*/
	results = atbm_kzalloc(512,GFP_KERNEL);
	
	if(results == NULL){
		ret = -ENOMEM;
		goto exit;
	}
	
	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = ATBM_SPACE;
	
	for(i = 0;i<wrqu->data.length;i++){
		if((ptr[i] == ATBM_LINEF) || 
		   (ptr[i] == ATBM_ENTER) || 
		   (ptr[i] == ATBM_TAIL) ||
		   (ptr[i] == ',')||(ptr[i] == 0)){
		   if(ptr[i] == ',')
		   		n_params ++;
		   ptr[i] = ATBM_SPACE;
		}
	}

	if(n_params > 0){
		atbm_printk_debug("%s:n_params (%d)\n",__func__,n_params);
		ret = -EINVAL;
		goto exit;
	}

	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		atbm_printk_debug("%s:2\n",__func__);
		ret = -EINVAL;
		goto exit;
	}
	
	pos = pos + strlen("stations_show");
	
	if(atbm_skip_space(pos,wrqu->data.length+1 - (pos-ptr))){
		atbm_printk_debug("%s:ptr err (%s)(%d)\n",__func__,pos,wrqu->data.length+1 - (pos-ptr));
		ret = -EINVAL;
		goto exit;
	}

	copy_len = scnprintf(results+total_len,512-total_len,"station show -->\n");
	total_len += copy_len;
	
	mutex_lock(&local->sta_mtx);
	list_for_each_entry_rcu(sta, &local->sta_list, list) {
		struct wsm_sta_info_req req;
		struct wsm_sta_info     info;
		if((sta->sdata != sdata) || 
		   (sta->uploaded == false) || 
		   (sta->dead == true) ||
		   (test_sta_flag(sta, WLAN_STA_AUTHORIZED) == 0)){
			continue;
		}
		req.flags = WSM_STA_REQ_FLAGS__TXRATE;
		memcpy(req.mac,sta->sta.addr,6); 
		atbm_req_sta_info(local->hw.priv,&req,&info,0);
		/*
		*mac,rss and rate;
		*/
		copy_len = scnprintf(results + total_len,512-total_len,"mac[%pM],rssi[%d],bg[%x],11n[%x],txrate[%d]\n",
		sta->sta.addr,(s8)-atbm_ewma_read(&sta->avg_signal2),sta->sta.supp_rates[chan_state->oper_channel->band],
		sta->sta.ht_cap.mcs.rx_mask[0],info.tx_rate);
		
		if(copy_len > 0)
			total_len += copy_len;
		else {
			break;
		}		
	}
	mutex_unlock(&local->sta_mtx);
	if(extra){
		memcpy(extra,results,total_len);	
		wrqu->data.length = total_len + 1;
	}
	
exit:
	if(ptr)
		atbm_kfree(ptr);
	if(results)
		atbm_kfree(results);
	return ret;
}
/*
*iface receive special type package 0xf0
*/
/*
static int atbm_ioctl_subtype(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	return 0;
}
*/

/*
*gpio config iwpriv wlan0 common gpio_conf,gpio,dir,pup or pud  
*/
static int atbm_ioctl_gpio_config(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv = (struct atbm_common *)local->hw.priv;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	char *ptr = NULL;
	char const *pos = NULL;
	char const *pos_end = NULL;
	int ret = 0;
	int i   = 0;
	int len = 0;
	int gpio = 0;
	int dir = 0;
	int pup = 0;

	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret =  -ENOMEM;
		goto exit;
	}
	
	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(ptr[i] == ',')
			ptr[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("gpio_conf");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - ptr);

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos+1;
	
	/*
	*parase gpio
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,gpio,atbm_accsii_to_int,false,exit,ret);
	/*
	*parase dir
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,dir,atbm_accsii_to_int,false,exit,ret);	
	if((dir != 0)&&(dir != 1)){
		ret = -EINVAL;
		goto exit;
	}
	/*
	*process pup
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,pup,atbm_accsii_to_int,false,exit,ret);
	if((pup != 0)&&(pup != 1)){
		ret = -EINVAL;
		goto exit;
	}
	/*
	*set gpio config
	*/
	atbm_printk_err("%s:gpio[%d],dir[%d],pup[%d]\n",__func__,gpio,dir,pup);
	ret = atbm_internal_gpio_config(hw_priv,gpio,dir?true:false,pup ? true:false,false);
	
exit:
	if(ptr)
		atbm_kfree(ptr);
	
	return ret;
}
/*
*gpio config iwpriv wlan0 common gpio_output,gpio,val  
*/
static int atbm_ioctl_gpio_output(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv = (struct atbm_common *)local->hw.priv;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	char *ptr = NULL;
	char const *pos = NULL;
	char const *pos_end = NULL;
	int ret = 0;
	int i   = 0;
	int len = 0;
	int gpio = 0;
	int val = 0;

	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret =  -ENOMEM;
		goto exit;
	}
	
	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(ptr[i] == ',')
			ptr[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("gpio_out");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - ptr);

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos+1;
	
	/*
	*parase gpio
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,gpio,atbm_accsii_to_int,false,exit,ret);
	/*
	*parase dir
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,val,atbm_accsii_to_int,false,exit,ret);	
	if((val != 0)&&(val != 1)){
		ret = -EINVAL;
		goto exit;
	}
	atbm_printk_err("%s:gpio[%d],val[%d]\n",__func__,gpio,val);
	ret = atbm_internal_gpio_output(hw_priv,gpio,val ? true: false);
exit:
	if(ptr)
		atbm_kfree(ptr);

	return ret;
}
/*
u16 txop;
u16 cw_min;
u16 cw_max;
u8 aifs;

*edca_params iwpriv wlan0 common edca_params,queue,aifs,cw_min,cw_max,txop  
*/
static int atbm_ioctl_edca_params(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	//struct ieee80211_local *local = sdata->local;
	//struct atbm_common *hw_priv = (struct atbm_common *)local->hw.priv;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	char *ptr = NULL;
	char const *pos = NULL;
	char const *pos_end = NULL;
	int ret = 0;
	int i   = 0;
	int queue = 0;
	int aifs = 0;
	int cw_min = 0;
	int cw_max = 0;
	int txop   = 0;
	int len = 0;

	if (!ieee80211_sdata_running(sdata)){
		ret =  -ENETDOWN;
		goto exit;
	}
	
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);
	
	if(!ptr){
		ret =  -ENOMEM;
		goto exit;
	}
	
	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
	ptr[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(ptr[i] == ',')
			ptr[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("edca_params");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - ptr);

	if(len <= 0){
		ret = -EINVAL;
		goto exit;
	}

	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos+1;
	
	/*
	*parase queue
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,queue,atbm_accsii_to_int,false,exit,ret);
	if((queue < 0) || (queue >= 4)){
		ret = -EINVAL;
		goto exit;
	}
	
	/*
	*parase aifs
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,aifs,atbm_accsii_to_int,false,exit,ret);	
	
	if((aifs < 0) || (aifs > 0xff)){
		ret = -EINVAL;
		goto exit;
	}

	/*
	*parase cw_min
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,cw_min,atbm_accsii_to_int,false,exit,ret);	
	
	if((cw_min < 0) || (cw_min > 0xffff)){
		ret = -EINVAL;
		goto exit;
	}

	/*
	*parase cw_max
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,cw_max,atbm_accsii_to_int,false,exit,ret);	
	
	if((cw_max < 0) || (cw_max > 0xffff)){
		ret = -EINVAL;
		goto exit;
	}
	
	/*
	*parase txop
	*/
	ATBM_WEXT_PROCESS_PARAMS(pos,len,txop,atbm_accsii_to_int,false,exit,ret);	
	
	if((txop < 0) || (txop > 0xffff)){
		ret = -EINVAL;
		goto exit;
	}
	atbm_printk_err("%s:queue[%d],aifs[%d],cw_min[%d],cw_max[%d],txop[%d]\n",sdata->name,queue,aifs,
	cw_min,cw_max,txop);

	if(atbm_internal_edca_update(sdata,queue,aifs,cw_min,cw_max,txop) == false){
		ret = -EINVAL;
		goto exit;
	}
exit:
	if(ptr)
		atbm_kfree(ptr);

	return ret;
}
/*

queue:
	0:voice traffic
	1:video traffic
	2:best effort
	3:background trafic

u16 txop;
u16 cw_min;
u16 cw_max;
u8 aifs;

*edca_params iwpriv wlan0 common get_edca_params  
*/

static int atbm_ioctl_get_edca_params(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0,i;
	
	//unsigned char *ptr = NULL;
	const char queue_string[][20]={
		"voice_traffic",
		"video_traffic",
		"best_effort",
		"background_trafic"
	};
	struct edca_data{
	/* CWmin (in slots) for the access class. */
	/* [in] */ u16 cwMin;

	/* CWmax (in slots) for the access class. */
	/* [in] */ u16 cwMax;

	/* AIFS (in slots) for the access class. */
	/* [in] */ u8 aifns;

	/* TX OP Limit (in microseconds) for the access class. */
	/* [in] */ u16 txOpLimit;
	};
	struct edca_data edca_value[4];
	
//	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
//	struct ieee80211_local *local;
//	struct atbm_common *hw_priv;
	struct atbm_vif *priv;

	if (!ieee80211_sdata_running(sdata)){
		atbm_printk_err("sdata not running \n");
		ret =  -ENETDOWN;
		goto exit1;
	}
	
//	local = sdata->local;
//	hw_priv=local->hw.priv;
	priv = (struct atbm_vif *)sdata->vif.drv_priv;
	
//	ptr = wdata->data.pointer;
	

	for(i = 0; i < 4;i++){
		atbm_printk_err("[%s] \n",queue_string[i]);
		atbm_printk_err("aifns : %d \n",priv->edca.params[i].aifns);
		atbm_printk_err("cwMax : %d \n",priv->edca.params[i].cwMax);
		atbm_printk_err("cwMin : %d \n",priv->edca.params[i].cwMin);
		atbm_printk_err("txOpLimit : %d \n",priv->edca.params[i].txOpLimit);
		edca_value[i].aifns = priv->edca.params[i].aifns;
		edca_value[i].cwMax = priv->edca.params[i].cwMax;
		edca_value[i].cwMin = priv->edca.params[i].cwMin;
		edca_value[i].txOpLimit = priv->edca.params[i].txOpLimit;
	}
	if(extra){	
		memcpy(extra, (char *)edca_value, sizeof(struct edca_data) * 4);	
		wrqu->data.length = sizeof(struct edca_data);
	}
	
exit1:
	return ret;

}

static int atbm_ioctl_get_txposer_status(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{

	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct power_status_t tx_power_status;
	int ret = -1;
	
	memset(&tx_power_status, 0, sizeof(tx_power_status));
	if((ret=wsm_get_tx_power_status(hw_priv, &tx_power_status, sizeof(tx_power_status))) == 0){
		atbm_printk_always("current TX power status:b[%d/10]dB,20M gn[%d/10dB],40M gn[%d/10]dB\n",
			tx_power_status.b_txpower_delta_value_multiple_10,
			tx_power_status.gn_20m_txpower_delta_value_multiple_10,
			tx_power_status.gn_40m_txpower_delta_value_multiple_10);
	}
	else{
		atbm_printk_err("get tx power status failed\n");
	}

	return ret;
}

#ifdef CUSTOM_FEATURE_MAC /* To use macaddr and ps mode of customers */
extern int access_file(char *path, char *buffer, int size, int isRead);
#endif
#ifdef CONFIG_TXPOWER_DCXO_VALUE
//txpower and dcxo config file
#define STR_FILE CONFIG_TXPOWER_DCXO_VALUE
#else
#define STR_FILE "/tmp/atbm_txpwer_dcxo_cfg.txt"
#endif

//extern void atbm_get_delta_gain(char *srcData,int *allgain,int *bgain,int *gngain);
static int atbm_ioctl_set_txpwr_by_file(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{

	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int ret = -1;
	int if_id = -1;
	char readbuf[256] = "";
	int deltagain[4]={0};
	int bgain[3]={0};
	int gngain[3]={0};
	
	//use delta_gain and dcxo value in config file,when file is exist
#ifdef CUSTOM_FEATURE_MAC
	if(access_file(STR_FILE,readbuf,sizeof(readbuf),1) > 0)
	{
		atbm_printk_init("param:%s",readbuf);
		atbm_get_delta_gain(readbuf,deltagain,bgain,gngain);
		memset(readbuf, 0, sizeof(readbuf));
		sprintf(readbuf, "set_txpwr_and_dcxo,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d ",deltagain[0], deltagain[1], deltagain[2], deltagain[3],
			bgain[0], bgain[1], bgain[2],gngain[0], gngain[1], gngain[2]);
		if(deltagain[3]==0)
			deltagain[3] = hw_priv->efuse.dcxo_trim;
		atbm_printk_init("cmd: %s\n", readbuf);
		ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD, readbuf, strlen(readbuf), if_id);
		if(ret < 0){
			atbm_printk_err("write mib failed(%d). \n", ret);
		}
	}
#endif

	return ret;
}

extern int get_rate_delta_gain(s8 *dst);
static int atbm_ioctl_set_rate_txpwr_by_file(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int i,ret = -1,strheadLen = 0;
	//int if_id = -1;
	int useFlag = 0;
	//s8 rate_txpower[23] = {0};//validfalg,data
	char *pbuffer = NULL;
	char *pRxData = NULL;
	

	if(!(pbuffer = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(pbuffer, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(pbuffer);
		return -EINVAL;
	}
	pbuffer[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(pbuffer[i] == ',')
		{
			strheadLen=i;
			break;
		}
	}
	
	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, pbuffer, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(pbuffer);
		return -EINVAL;
	}

	pRxData = &pbuffer[strheadLen];
	atbm_printk_err("cmd:%s\n", pRxData);
	CmdLine_GetSignInteger(&pRxData, &useFlag);
#ifdef CONFIG_RATE_TXPOWER
/*
	get_rate_delta_gain(&rate_txpower[0]);
	for(i=22;i>11;i--)
		rate_txpower[i] = rate_txpower[i-1];
	rate_txpower[11] = useFlag;
	{
		ret = wsm_write_mib(hw_priv, WSM_MIB_ID_SET_RATE_TX_POWER, rate_txpower, sizeof(rate_txpower), if_id);
		if(ret < 0){
			atbm_printk_err("write mib failed(%d). \n", ret);
		}
	}
	*/
	wsm_set_rate_power(hw_priv,useFlag);
#else
	atbm_printk_err("undefine CONFIG_RATE_TXPOWER,so Not support\n");
#endif
	if(pbuffer)
		atbm_kfree(pbuffer);

	return ret;
}

static int atbm_ioctl_set_management_frame_rate(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	//union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int i,ret = -1,strheadLen = 0;
	int if_id = -1;
	int rateIndex = 0;
	char *pbuffer = NULL;
	char *pRxData = NULL;

	if(!(pbuffer = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(pbuffer, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(pbuffer);
		return -EINVAL;
	}
	pbuffer[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(pbuffer[i] == ',')
		{
			strheadLen=i;
			break;
		}
	}
	
	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, pbuffer, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(pbuffer);
		return -EINVAL;
	}

	pRxData = &pbuffer[strheadLen];
	atbm_printk_err("cmd:%s\n", pRxData);
	CmdLine_GetSignInteger(&pRxData, &rateIndex);
	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_SET_BEACON_RATE, &rateIndex, sizeof(rateIndex), if_id);
	if(ret < 0){
		atbm_printk_err("write mib failed(%d). \n", ret);
	}

	if(pbuffer)
		atbm_kfree(pbuffer);

	return ret;
}

int get_work_channel(struct ieee80211_sub_if_data *sdata)
{
	unsigned short channel = 0;
  	struct ieee80211_local *local = sdata->local;
	struct ieee80211_channel_state *chan_state = NULL;
	struct ieee80211_sub_if_data *sdata_update;    
	
	mutex_lock(&local->mtx);

	list_for_each_entry(sdata_update, &local->interfaces, list){		

//		atbm_printk_err("%s,current work channel is [%d]\n", __func__,ieee80211_get_channel_mode(local, sdata_update));
		if(ieee80211_get_channel_mode(local, sdata_update) == CHAN_MODE_FIXED || 
		   ieee80211_get_channel_mode(local, sdata_update) == CHAN_MODE_HOPPING){
		    channel = 1;
			break;
		}
	}
	if(channel == 1){
		chan_state = ieee80211_get_channel_state(local, sdata_update);
		if(chan_state)
			channel = channel_hw_value(chan_state->oper_channel);
		else
			channel = 0;
	}
#ifdef CONFIG_ATBM_STA_LISTEN
	else{
		
		if(local->listen_channel)
			channel = channel_hw_value(local->listen_channel);
		else
			channel = 0;
	}
#endif
	/*
	chan_state = ieee80211_get_channel_state(local, sdata);
	if((ieee80211_get_channel_mode(local, NULL) == CHAN_MODE_FIXED) && (chan_state)){
		channel = channel_hw_value(chan_state->oper_channel);
	}else {
		channel = 0;
	}
	*/
	mutex_unlock(&local->mtx);
	return channel;

}
static int atbm_ioctl_get_work_channel(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
	unsigned short channel = 0;
    struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
  	channel = get_work_channel(sdata);
	atbm_printk_err("%s,current work channel is [%d]\n", __func__,channel);
   
    if(ext){	
		sprintf(ext,"\ncurrent work channel:%d\n",channel);
		//memcpy(ext,(char *)&channel,sizeof(channel));	
		wrqu->data.length = strlen(ext);
	}
    return 0;

}
static int atbm_ioctl_set_country_code(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{

#ifdef  CONFIG_ATBM_5G_PRETEND_2G
	atbm_printk_err(" Not only 2.4G mode not support set country code! \n");
	return 0;
#else
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	unsigned char *country_code = NULL;
	char *pbuffer = NULL;
	int ret = 0,i,strheadLen = 0;
	
	if(!ieee80211_sdata_running(sdata)){
		ret = -ENETDOWN;
		goto exit;
	}
	if(!(pbuffer = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		return -EINVAL;
	}
	if((ret = copy_from_user(pbuffer, wrqu->data.pointer, wrqu->data.length))){
		atbm_kfree(pbuffer);
		return -EINVAL;
	}
	pbuffer[wrqu->data.length] = 0;

	for(i=0;i<wrqu->data.length;i++)
	{
		if(pbuffer[i] == ',')
		{
			strheadLen=i;
			break;
		}
	}

	atbm_printk_err("length=%d,data=%s,strheadLen=%d\n", wrqu->data.length, pbuffer, strheadLen);
	if (strheadLen >= wrqu->data.length){
		atbm_kfree(pbuffer);
		return -EINVAL;
	}
	
	country_code = &pbuffer[strheadLen+1];
#ifdef CONFIG_CFG80211_INTERNAL_REGDB 
		if(atbm_set_country_code_to_cfg80211(local,country_code) < 0){
			ret = -EINVAL;
			goto exit;
		}
#else
	memcpy(local->country_code,country_code,2);
#endif
	ret = 0;
	atbm_printk_err("atbm_dev_set_country_code:country_code = %c%c---------------\n",local->country_code[0],local->country_code[1]);
exit:
	return ret;
#endif		
}

static int atbm_ioctl_get_country_code(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
#ifdef  CONFIG_ATBM_5G_PRETEND_2G
	atbm_printk_err("atbm_ioctl_get_country_code: Not only 2.4G mode not support set country code! \n");
	return 0;
#else
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	atbm_printk_err("atbm_dev_set_country_code:country_code = %c%c---------------\n",
					local->country_code[0],local->country_code[1]);		
	 if(ext){	
		sprintf(ext,"\ncurrent country_code is:%c%c\n",local->country_code[0],local->country_code[1]);
		wrqu->data.length = strlen(ext);
	}
	return 0;
#endif
}



static int atbm_set_power_save_mode(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *ext)
{
//static int atbm_set_power_save_mode(struct ieee80211_hw *hw,u8 *data, int len)

	
	int ps_elems = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	int i,strheadLen = 0;
	char *buff_data =NULL;

	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		return  -EINVAL;
	}
	
	if(sdata->u.mgd.associated == NULL){
		return  -EINVAL;
	}
	
	buff_data = atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);

	if(buff_data == NULL){
		atbm_printk_wext("%s atbm_kzalloc error!\n",__func__);
		return  -EINVAL;
	}
	
	if(copy_from_user(buff_data, wrqu->data.pointer, wrqu->data.length)){
		atbm_printk_wext("%s copy_from_user error!\n",__func__);
		atbm_kfree(buff_data);
		return -EINVAL;
	}
	buff_data[wrqu->data.length] = 0;
	for(i=0;i<wrqu->data.length;i++)
	{
		if(buff_data[i] == ',')
		{
			strheadLen=i+1;
			break;
		}
	}
	
	
	ps_elems = buff_data[strheadLen];

	if (ps_elems == 0x30)
		sdata->u.mgd.powersave_enable = false;
	else
		sdata->u.mgd.powersave_enable = true;

	ieee80211_recalc_ps(local, -1);
	
	atbm_kfree(buff_data);
	return 0;
}


static int atbm_ioctl_get_cfg_txpower_by_file(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = -EINVAL,i = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct cfg_txpower_t configured_txpower;
	const char *ratebuf[11] = {"b_1M_2M",
							"b_5_5M_11M",
							"g_6M_n_6_5M",
							"g_9M",
							"g_12M_n_13M",
							"g_18M_n_19_5M",
							"g_24M_n_26M",
							"g_36M_n_39M",
							"g_48M_n_52M",
							"g_54M_n_58_5M",
							"n_65M"};

	memset(&configured_txpower,0, sizeof(configured_txpower));
#if defined CONFIG_TXPOWER_DCXO_VALUE || defined CONFIG_RATE_TXPOWER
	if ((ret = wsm_get_cfg_txpower(hw_priv, (void *)&configured_txpower, sizeof(configured_txpower))) == 0){	
		for(i=0;i<sizeof(configured_txpower.set_txpwr_delta_gain);i++)
			atbm_printk_err("gain%d:%d\n",i+1,configured_txpower.set_txpwr_delta_gain[i]);
		for(i=0;i<sizeof(configured_txpower.set_b_txpwr_delta_gain);i++)
			atbm_printk_err("bgain%d:%d\n",i+1,configured_txpower.set_b_txpwr_delta_gain[i]);
		for(i=0;i<sizeof(configured_txpower.set_gn_txpwr_delta_gain);i++)
			atbm_printk_err("gngain%d:%d\n",i+1,configured_txpower.set_gn_txpwr_delta_gain[i]);  
		for(i=0;i<sizeof(configured_txpower.different_rate_txpower_mode);i++)
			atbm_printk_err("%s:%d\n",ratebuf[i],configured_txpower.different_rate_txpower_mode[i]);
		for(i=0;i<sizeof(configured_txpower.different_rate_txpower_mode_40M);i++)
			atbm_printk_err("%s_40M:%d\n",ratebuf[i],configured_txpower.different_rate_txpower_mode_40M[i]);
	}
	else{
		atbm_printk_err("read configured tx power failed\n");
	}
#else
	atbm_printk_err("undefine CONFIG_RATE_TXPOWER or CONFIG_TXPOWER_DCXO_VALUE,so Not support\n");
#endif

	return ret;
}

#ifdef CONFIG_ATBM_GET_GPIO4
extern int atbm_direct_write_reg_32(struct atbm_common *hw_priv, u32 addr, u32 val);
extern int atbm_direct_read_reg_32(struct atbm_common *hw_priv, u32 addr, u32 *val);
extern int atbm_usb_write_bit(struct atbm_common *hw_priv,u32 addr,u8 endBit,u8 startBit,u32 data );
bool gpio_input_value(struct atbm_common *hw_priv, u32 channel_no){
	u32 reg_value = 0;
	
	atbm_direct_read_reg_32(hw_priv, 0x16800020, &reg_value);
	return ((reg_value>>channel_no) & 0x01);
}

void gpio_input_config(struct atbm_common *hw_priv, u32 channel_no){
	u32 reg_dir = 0;

	atbm_direct_read_reg_32(hw_priv, 0x16800028, &reg_dir);
	reg_dir &= ~(1<<channel_no);
	atbm_direct_write_reg_32(hw_priv, 0x16800028, reg_dir);
}

void gpio_output_config(struct atbm_common *hw_priv, u32 channel_no){
	u32 reg_dir = 0;

	atbm_direct_read_reg_32(hw_priv, 0x16800028, &reg_dir);
	reg_dir |= (1<<channel_no);
	atbm_direct_write_reg_32(hw_priv, 0x16800028, reg_dir);
}


int gpio_set_pin_func(struct atbm_common *hw_priv, int channel_no,int func)
{
	int gpio_id= channel_no;
	u32 regaddr = 0;
	if(channel_no > 24){
		return ;
	}
	if(channel_no == 22 || channel_no == 23)
	{
		atbm_usb_write_bit(hw_priv, 0x17400000,8,8,1);
	}	
		
	func = func&0x7;
	regaddr = 0x17400000+(channel_no/2)*4+4;
	if(channel_no&1){
		atbm_usb_write_bit(hw_priv, regaddr,19,16,func);
	}
	else {
		atbm_usb_write_bit(hw_priv, regaddr,3,0,func); 	
	}
	

	return 0;
}

void gpio_pull_value(struct atbm_common *hw_priv, u32 channel_no,bool value)
{

	//Ares_B
	u32 regaddr;
	if(channel_no == 22 || channel_no == 23)
	{
		atbm_usb_write_bit(hw_priv, 0x17400000,8,8,1);
	}

	regaddr = 0x17400000+(channel_no/2)*4+4;
	if(value&0x01)
	{
		if(channel_no&1)
		{
			atbm_usb_write_bit(hw_priv, regaddr,27,27,1);      //GPIO23
			atbm_usb_write_bit(hw_priv, regaddr,28,28,0);      //GPIO23
		}
		else
		{
			atbm_usb_write_bit(hw_priv, regaddr,11,11,1);      //GPIO22
			atbm_usb_write_bit(hw_priv, regaddr,12,12,0);      //GPIO22
		}
	}
	else
	{
		if(channel_no&1)
		{
			atbm_usb_write_bit(hw_priv, regaddr,27,27,0);      //GPIO23
			atbm_usb_write_bit(hw_priv, regaddr,28,28,1);      //GPIO23
		}
		else
		{
			atbm_usb_write_bit(hw_priv, regaddr,11,11,0);      //GPIO22
			atbm_usb_write_bit(hw_priv, regaddr,12,12,1);      //GPIO22
		}
	}

}


int Atbm_Input_Value_Gpio(struct atbm_common *hw_priv, int channel_no)
{
	u32 inputVal = 0;

	//3:GPIO_FUNC_T
	gpio_set_pin_func(hw_priv, channel_no, 3);

	gpio_input_config(hw_priv, channel_no);

	inputVal = gpio_input_value(hw_priv, channel_no);

	return inputVal;
}
int readInputValueFromGPIO4(struct atbm_common *hw_priv)
{
	u32 reg_dir = 0;
	u32 reg_value = 0;
	u32 reg1740000c = 0;

	atbm_direct_read_reg_32(hw_priv, 0x1740000c, &reg1740000c);
	printk("0x1740000c:0x%x\n", reg1740000c);
	reg1740000c &= ~(BIT(3)|BIT(2)|BIT(1)|BIT(0));
	printk("0x1740000c:0x%x\n", reg1740000c);
	reg1740000c |= (BIT(1)|BIT(0));
	atbm_direct_write_reg_32(hw_priv, 0x1740000c, reg1740000c);
	atbm_direct_read_reg_32(hw_priv, 0x1740000c, &reg1740000c);
	printk("0x1740000c:0x%x\n", reg1740000c);

	atbm_direct_read_reg_32(hw_priv, 0x16800028, &reg_dir);
	reg_dir &= ~(BIT(4));
	atbm_direct_write_reg_32(hw_priv, 0x16800028, reg_dir);

	atbm_direct_read_reg_32(hw_priv, 0x16800020, &reg_value);

	printk("0x16800020:0x%x,%d \n", reg_value, (reg_value & BIT(4)));
	return (reg_value & BIT(4));
}

int atbm_ioctl_get_gpio4(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra){
	int gpio_data = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hw *hw = &local->hw;
	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;
	gpio_data = readInputValueFromGPIO4(hw_priv);
	if(extra){
		memcpy((char *)extra, (char *)&gpio_data,sizeof(int));
		wrqu->data.length = sizeof(int);
	}
	return  gpio_data;
}

#endif

int atbm_ioctl_get_cfo_cali_data(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hw *hw = &local->hw;
	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;
	u8 dcxo = 0;
	u8 crystal_type = 0;
	int cfo_val = 0;

	crystal_type = GetChipCrystalType(hw_priv);
	
	dcxo = DCXOCodeRead(hw_priv);

	wsm_get_cfo_ppm_correction_value(hw_priv,&cfo_val,sizeof(int));
	
	atbm_printk_always("%s,dcxo:%d ,cfo_val:%d ppm \n", crystal_type==2?"share crystal":"independent crystal", dcxo,cfo_val);

	if(extra){
		sprintf(extra,"\n%s,dcxo:%d,cfo:%dppm\n",crystal_type==2?"share crystal":"independent crystal",dcxo,cfo_val);
    	wrqu->data.length = strlen(extra);
	}
	
	return  0;
}


int atbm_ioctl_send_vendor_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
//	struct ieee80211_local *local = sdata->local;
	//struct ieee80211_hw *hw = &local->hw;
//	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;
	struct atbm_vendor_cfg_ie private_ie;
	char *data = NULL,*ptr,*str;
	int i,cmd_len,ssid_len,pw_len,ret = 0,num=0;
	u8 channels[14] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};
	int chan = 0;
	int j = 0;
	
	if (!ieee80211_sdata_running(sdata)){
		atbm_printk_err("net interface not runing! \n");
		ret =  -EINVAL;
		goto exit;

	}

	data = (char *)atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);
	if(data == NULL){
		ret =  -ENOMEM;
		goto exit;
	}
	if(copy_from_user((void *)data, wrqu->data.pointer, wrqu->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
//	str = strchr(data,',');
//	ptr = strchr(str+1,',');

	str = NULL;
	ptr = NULL;
	for(i=0;i<wrqu->data.length;i++){
		if((data[i] == ',') && (num == 0)){
				num++;
				str = data + i;//ssid
		}
		else if((data[i] == ',') && (num == 1)){
			ptr = data + i ;//psk
			break;
		}
	}
	if(!str || !ptr){
		atbm_printk_err("atbm_ioctl_send_probe_resp , Data parsing error! ,data = %s\n",data);
		goto exit;
	}
	cmd_len = str - data;
	ssid_len = ptr - str -1;
	pw_len = wrqu->data.length - cmd_len - ssid_len - 2 -1;
	
	
	memset(&private_ie,0,sizeof(struct atbm_vendor_cfg_ie));
	private_ie.ie_id = 221;
	private_ie.OUI[0] = (ATBM_6441_PRIVATE_OUI >> 24) & 0xFF;
	private_ie.OUI[1] = (ATBM_6441_PRIVATE_OUI >> 16) & 0xFF;
	private_ie.OUI[2] = (ATBM_6441_PRIVATE_OUI >> 8) & 0xFF;
	private_ie.OUI[3] = ATBM_6441_PRIVATE_OUI & 0xFF;
	memcpy(private_ie.ssid,str+1,ssid_len);
	private_ie.ssid_len = ssid_len;
	memcpy(private_ie.password,ptr+1,pw_len);
	private_ie.password_len = pw_len;
	private_ie.ie_len = sizeof(struct atbm_vendor_cfg_ie) - 2;

	
	
	chan = get_work_channel(sdata);

	atbm_printk_err("ssid=%s , ssid_len = %d,psk=%s,psk_len=%d ,channel = %d\n",
			private_ie.ssid,private_ie.ssid_len,private_ie.password,private_ie.password_len,chan);
	
	
	if(chan > 14 || chan < 1){
		for(j=0;j<14;j++)
			channels[j] = j+1;
	}else{
		for(j=0;j<14;j++)
			channels[j] = chan;
	}
	ieee80211_sta_triger_positive_scan(sdata,channels,14,NULL,0,
				(u8 *)&private_ie,sizeof(struct atbm_vendor_cfg_ie),NULL);
	ret = 0;
	
exit:
	if(data)
		atbm_kfree(data);
	return ret;
}

static int atbm_ioctl_send_probe_resp(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hw *hw = &local->hw;
	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;
//	struct sk_buff *skb = NULL;
	
	struct atbm_vendor_cfg_ie private_ie;
	char *data = NULL,*ptr,*str;
	int i,cmd_len,ssid_len,pw_len,ret = 0,num = 0;

	if (!ieee80211_sdata_running(sdata)){
		atbm_printk_err("net interface not runing! \n");
		ret =  -EINVAL;
		goto exit;

	}
	if(sdata->vif.type != NL80211_IFTYPE_AP){
		atbm_printk_err("atbm_ioctl_send_probe_resp , not ap mode! \n");
		return false;
	}

	
	data = (char *)atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);
	if(data == NULL){
		ret =  -ENOMEM;
		goto exit;
	}
	if(copy_from_user((void *)data, wrqu->data.pointer, wrqu->data.length)){
		ret =  -EINVAL;
		goto exit;
	}
	
//	str = strchr(data,',');
//	ptr = strchr(str+1,',');
	str = NULL;
	ptr = NULL;
	for(i=0;i<wrqu->data.length;i++){
		if((data[i] == ',') && (num == 0)){
				num++;
				str = data + i;//ssid
		}
		else if((data[i] == ',') && (num == 1)){
			ptr = data + i ;//psk
			break;
		}
	}
	if(!str || !ptr){
		atbm_printk_err("atbm_ioctl_send_probe_resp , Data parsing error! ,data = %s\n",data);
		goto exit;
	}
	
	cmd_len = str - data;
	ssid_len = ptr - str -1;
	pw_len = wrqu->data.length - cmd_len - ssid_len - 2 -1;
	
	
	memset(&private_ie,0,sizeof(struct atbm_vendor_cfg_ie));
	private_ie.ie_id = 221;
	private_ie.OUI[0] = (ATBM_6441_PRIVATE_OUI >> 24) & 0xFF;
	private_ie.OUI[1] = (ATBM_6441_PRIVATE_OUI >> 16) & 0xFF;
	private_ie.OUI[2] = (ATBM_6441_PRIVATE_OUI >> 8) & 0xFF;
	private_ie.OUI[3] = ATBM_6441_PRIVATE_OUI & 0xFF;
	memcpy(private_ie.ssid,str+1,ssid_len);
	private_ie.ssid_len = ssid_len;
	memcpy(private_ie.password,ptr+1,pw_len);
	private_ie.password_len = pw_len;
	private_ie.ie_len = sizeof(struct atbm_vendor_cfg_ie) - 2;

	atbm_printk_err("ssid=%s , ssid_len = %d,psk=%s,psk_len=%d \n",
			private_ie.ssid,private_ie.ssid_len,private_ie.password,private_ie.password_len);


	memcpy(&hw_priv->private_ie,&private_ie,sizeof(struct atbm_vendor_cfg_ie)); 
	hw_priv->start_send_prbresp = true;
	wake_up(&hw_priv->send_prbresp_wq);
	//ieee80211_queue_work(&sdata->local->hw,&hw_priv->send_prbresp_work);

	ret = 0;
	
exit:
	if(data)
		atbm_kfree(data);
	return ret;
}
static int atbm_ioctl_stop_send_probe_resp(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hw *hw = &local->hw;
	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;

	if (!ieee80211_sdata_running(sdata)){
		atbm_printk_err("net interface not runing! \n");

		return  -EINVAL;

	}
	if(sdata->vif.type != NL80211_IFTYPE_AP){
		atbm_printk_err("atbm_ioctl_stop_send_probe_resp , not ap mode! \n");
		return false;
	}

	

	hw_priv->start_send_prbresp = false;
	

	atbm_printk_err("atbm_ioctl_stop_send_probe_resp! \n");
	return 0;
}

int atbm_ioctl_get_vendor_ie(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct atbm_vendor_cfg_ie *private_ie;
	private_ie = atbm_internal_get_6441_vendor_ie();
	if(!private_ie){
		atbm_printk_err("not recive 6441 vendor ie!");
		return -1;
	}
	atbm_printk_err("atbm_ioctl_get_vendor_ie : ssid[%s],password[%s] \n",private_ie->ssid,private_ie->password);

	if(extra){
		sprintf(extra,"\nie_id:%d\nie_len:%d\nOUI:%02x %02x %02x %02x\nssid:%s\nssid_len:%d\npassword:%s\npassword_len:%d\n",
			private_ie->ie_id,private_ie->ie_len,private_ie->OUI[0],private_ie->OUI[1],private_ie->OUI[2],private_ie->OUI[3],
			private_ie->ssid,private_ie->ssid_len,private_ie->password,private_ie->password_len);
		//memcpy(extra, private_ie,sizeof(struct atbm_vendor_cfg_ie));
	//	wrqu->data.length = sizeof(struct atbm_vendor_cfg_ie) + 1;
		wrqu->data.length = strlen(extra);
	}	

	return 0;
}

#ifdef CONFIG_ATBM_AP_CHANNEL_CHANGE_EVENT
extern void ieee80211_start_ap_changechannel_work(struct ieee80211_sub_if_data *ap_sdata,int channel,u8 chann_type);
extern void ieee80211_bss_info_change_notify(struct ieee80211_sub_if_data *sdata,u32 changed);
extern int ieee80211_set_channel(struct wiphy *wiphy,struct net_device *netdev,
										struct ieee80211_channel *chan,enum nl80211_channel_type channel_type);
int atbm_ioctl_change_ap_channel(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hw *hw = &local->hw;
	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;
	char * data = NULL;
	int channel = 0,chan_type = 0,freq = 0,ret = 0;
	struct ieee80211_channel * chan ;//=req->bss->channel;
 //	enum nl80211_channel_type channel_type ;//= NL80211_CHAN_HT20;	

	if(sdata->vif.type != NL80211_IFTYPE_AP){
		ret = -EOPNOTSUPP;
		goto exit;
	}
	
	

	data = (char *)atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);
	if(data == NULL){
		atbm_printk_err("data malloc  err!\n");
		ret =  -ENOMEM;
		goto exit;
	}
	if(copy_from_user((void *)data, wrqu->data.pointer, wrqu->data.length)){
		atbm_printk_err("copy_from_user  err!\n");
		ret =  -EINVAL;
		goto exit;
	}
	atbm_printk_err("atbm_ioctl_change_ap_channel:%s \n",data);
	sscanf(data,"change_chan,%d,%d",&channel,&chan_type);
	
	
	
	if(channel < 0 || channel > 14){
		atbm_printk_err("channel = %d  err!\n",channel);
		ret = -EINVAL;
		goto exit;
	}
	if(hw_priv->chip_version == ARES_6012B){
		if(chan_type)
			atbm_printk_err("WARNING!!!!chip_version is only support HT20 \n");
		chan_type = NL80211_CHAN_HT20;
	}else{
#ifndef ATBM_NOT_SUPPORT_40M_CHW
#ifdef ATBM_SUPPORT_WIDTH_40M	
		if(chan_type){
			if(channel < 6){
				chan_type = (NL80211_CHAN_HT40PLUS);//2
			}else{
				chan_type = (NL80211_CHAN_HT40MINUS);//3
			}
		}else
#endif
#endif
		{
			chan_type = NL80211_CHAN_HT20;//1
		}
	}
	if(channel == 14)
		freq = 2484;
	else{
		freq = (channel-1)*5 + 2412;
	}
	chan = ieee80211_get_channel(local->hw.wiphy, freq);
	if(chan == NULL){
		atbm_printk_err("ieee80211_get_channel  err!\n");
		ret = -EINVAL;
		goto exit;
	}
	atbm_printk_err("channel:%d , HT40:%d \n",channel,chan_type);	

	atbm_printk_err("ieee80211_start_ap_changechannel_tmp\n");
	//set channel change to hal
	ieee80211_set_channel(local->hw.wiphy,sdata->dev,chan,chan_type);
	//change AP beacon.prbrsp DSparam
	ieee80211_bss_info_change_notify(sdata,	BSS_CHANGED_BEACON|BSS_CHANGED_HT_CHANNEL_TYPE);
	/*set channel change to hostapd*/
	ieee80211_start_ap_changechannel_work(sdata,channel,chan_type);

exit:
	return ret;
}

#endif
int atbm_ioctl_set_listen_probe_req(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
//	struct ieee80211_local *local = sdata->local;
//	struct ieee80211_hw *hw = &local->hw;
//	struct atbm_common *hw_priv = (struct atbm_common *) hw->priv;
	int ret,wifi_status = 0,channel = 0;
	char * data = NULL;
	if (!ieee80211_sdata_running(sdata)){
		atbm_printk_err("net interface not runing! \n");
		ret =  -EINVAL;
		goto exit;

	}
	
	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		ret = -EOPNOTSUPP;
		goto exit;
	}
	
	
	
	data = (char *)atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);
	if(data == NULL){
		ret =  -ENOMEM;
		goto exit;
	}
	if(copy_from_user((void *)data, wrqu->data.pointer, wrqu->data.length)){
		ret =  -EINVAL;
		goto exit;
	}

	sscanf(data,"listen_probe_req,%d",&channel);
	//str = strchr(data,',');
	//channel = simple_strtol(str+1);
	if(channel < 0 || channel > 14){
		atbm_printk_err("channel = %d  err!\n",channel);
		ret = -EINVAL;
		goto exit;
	}

	wifi_status = atbm_wifi_status_get();
	atbm_printk_err("channel = %d wifi_status = %s\n",channel,wifi_status == 1?"CONNECTED":"DISCONNECT");
	if(wifi_status == 0){	
		ret = ieee80211_set_sta_channel(sdata,channel);
	}else{
		struct ieee80211_special_filter filter;
		memset(&filter,0,sizeof(struct ieee80211_special_filter));
		if(channel){
			filter.filter_action = 0x40;
			filter.flags = SPECIAL_F_FLAGS_FRAME_TYPE;
			atbm_printk_err("%s:action(%x)\n",__func__,filter.filter_action);
			ret = ieee80211_special_filter_register(sdata,&filter);	
		}else{
			ret = ieee80211_special_filter_clear(sdata);
		}
	}

exit:
	if(data)
		atbm_kfree(data);
	return ret;

}

#ifdef DEBUG_CHANNEL_PARAM

static int atbm_ioctl_get_cca_threshold(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int cca_threshold;
	ret = wsm_get_cca_threshold(hw_priv,&cca_threshold,sizeof(int));

	if(ret == 0){
		sprintf(extra,"\ncca_threshold:%d\n",cca_threshold);
	}else{
		sprintf(extra,"\ncca_threshold get fail\n");
	}
	wrqu->data.length = strlen(extra);
	return 0;
}
static int atbm_ioctl_get_rts_threshold(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int rts_threshold;
	ret = wsm_get_rts_threshold(hw_priv,&rts_threshold,sizeof(int));
	
	if(ret == 0){
		sprintf(extra,"\ncca_threshold:%d\n",rts_threshold);
	}else{
		sprintf(extra,"\ncca_threshold get fail\n");
	}
	wrqu->data.length = strlen(extra);
	return 0;
}

static int atbm_ioctl_get_rts_duration(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	int rts_duration;
	ret = wsm_get_rts_duration(hw_priv,&rts_duration,sizeof(int));
	if(ret == 0){
		sprintf(extra,"\nrts_duration:%d\n",rts_duration);
	}else{
		sprintf(extra,"\nrts_duration get fail\n");
	}
	wrqu->data.length = strlen(extra);
	return 0;
	
}

/*

struct RX_QA_STATUS_S{
	s8 initial_gain;
	s8 noise_level_dBm;
	u8 cca_indication;
	s8 update_gain;
	uint32 reserved;
};

*/

static int atbm_ioctl_get_noise_level(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct RX_QA_STATUS_S noise_level;
	//int noise_level;
	int noise_level_dBm = 0;
	memset(&noise_level,0,sizeof(noise_level));
	
	ret = wsm_get_noise_level(hw_priv,&noise_level,sizeof(struct RX_QA_STATUS_S));

	noise_level_dBm = noise_level.noise_level_dBm;
	if(noise_level_dBm > 127)
		noise_level_dBm -= 256;
	
	if(ret == 0){
		if(noise_level.initial_gain == 60)
			sprintf(extra,"\nexact noise_level_dBm = %d\n",noise_level_dBm);
		else
			sprintf(extra,"\ninitg = %d,reckon noise_level_dBm = %d\n",noise_level.initial_gain,noise_level_dBm);
	}
	
	wrqu->data.length = strlen(extra);
	
	return 0;
}

	

static int atbm_ioctl_get_snr(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;

	int snr_val = 0;
	//unsigned short snr = 0;
	
	ret = wsm_get_snr(hw_priv,&snr_val,sizeof(int));

	if(ret == 0){
		sprintf(extra,"\nlmac get snr_val = %d ,real snr = 10*log10(4096/%d)\n",snr_val,snr_val);
	}else{
		sprintf(extra,"\nsnr get fail\n");
	}
	wrqu->data.length = strlen(extra);
	return 0;
	
}

#ifdef CONFIG_JUAN_MISC

static int atbm_ioctl_common_get_tim(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct TIM_Parameters tim_val;
	int snr_val = 0;
	//unsigned short snr = 0;

	if(!ieee80211_sdata_running(sdata) && (sdata->vif.type != NL80211_IFTYPE_AP)){
		atbm_printk_err("atbm_ioctl_common_get_tim : not ap mode! \n");
		return -ENETDOWN;

	}

	
	ret = wsm_get_tim(hw_priv,&tim_val,sizeof(struct TIM_Parameters));
	
	if(ret == 0){
		sprintf(extra,"\nbeacon tim :%s,Bitmap control:0x%02x , Partial Virtual Bitmap:0x%x\n",tim_val.tim_user_control_ena==0?

"aotu control tim":"customer control tim",
			tim_val.tim_val & 0xff,tim_val.tim_val>>8);
	}else{
		sprintf(extra,"\beacon tim get fail\n");
	}
	wrqu->data.length = strlen(extra);
	return 0;
	
}

static int atbm_ioctl_common_set_tim(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct TIM_Parameters tim_val;
	char *tim_data = NULL;
	
	if(!ieee80211_sdata_running(sdata) && (sdata->vif.type != NL80211_IFTYPE_AP)){
		atbm_printk_err("atbm_ioctl_common_get_tim : not ap mode! \n");
		return -ENETDOWN;

	}


	tim_data = atbm_kzalloc(wrqu->data.length+1, GFP_KERNEL);
	
	if(tim_data == NULL){
		ret = -EINVAL;
		goto set_tim_exit;
	}

	if(copy_from_user(tim_data, wrqu->data.pointer, wrqu->data.length)){
		ret =  -EINVAL;
		goto set_tim_exit;
	}

	int enable,tim_bit;
	
	sscanf(tim_data,"set_tim,%d,%x",&enable,&tim_bit);
	atbm_printk_err("get data : ena:%d, val:%x \n",enable,tim_bit);
//	CmdLine_GetHex();
	tim_val.tim_user_control_ena = enable;
	tim_val.tim_val = tim_bit;
	
	ret = wsm_set_tim(hw_priv,&tim_val,sizeof(struct TIM_Parameters));

	if(ret == 0){
		sprintf(extra,"\nset_tim success\n");
	}else{
		sprintf(extra,"\nset_tim fail\n");
	}
	wrqu->data.length = strlen(extra);

	//ret = 0;
set_tim_exit:
	if(tim_data)
		atbm_kfree(tim_data);
	return ret;
	
}

#endif

#endif



#ifdef CONFIG_ATBM_BLE_ADV_COEXIST
static int atbm_ioctl_ble_coexist_cmd(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct wsm_ble_msg_coex_start ble_coex = {0};
	int ret = -1;
	char *pbuffer = NULL;
	int ble_en = 0;
	int ble_interval = 0;
	int ble_adv = 0;
	int ble_scan = 0;
	int ble_scan_win = 0;
	int ble_adv_chan = 0;
	int ble_scan_chan = 0;
	
	if(!(pbuffer = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		goto EXIT;
	}

	if((ret = copy_from_user(pbuffer, wrqu->data.pointer, wrqu->data.length))){
		atbm_printk_err("copy_from_user failed!\n");
		goto EXIT;
	}
	
	pbuffer[wrqu->data.length] = 0;

	sscanf(pbuffer,"enable,%d",&ble_en);
	sscanf(pbuffer,"interval,%d",&ble_interval);
	sscanf(pbuffer,"adv,%d",&ble_adv);
	sscanf(pbuffer,"scan,%d",&ble_scan);
	sscanf(pbuffer,"scan_win,%d",&ble_scan_win);
	sscanf(pbuffer,"adv_chan,%d",&ble_adv_chan);
	sscanf(pbuffer,"scan_chan,%d",&ble_scan_chan);

	atbm_printk_init("ble_en:%d,ble_interval:%d,ble_adv:%d,ble_scan:%d,ble_scan_win:%d,ble_adv_chan:%d,ble_scan_chan:%d\n",
						ble_en, ble_interval, ble_adv, ble_scan, ble_scan_win, ble_adv_chan, ble_scan_chan);

	if(ble_en){
		if((ble_adv == 0) && (ble_scan == 0)){
			atbm_printk_err("both adv and scan is close!\n");
			goto EXIT;
		}
		
		if((ble_scan) && (ble_scan_win == 0)){
			atbm_printk_err("ble scan enable, but scan_win is 0!\n");
			goto EXIT;
		}
		
		if((ble_adv_chan != 0) && (ble_adv_chan >= 37) && (ble_adv_chan <= 39)){
			ble_coex.chan_flag |= BIT(ble_adv_chan - 37);
		}
		
		if((ble_scan_chan != 0) && (ble_scan_chan >= 37) && (ble_scan_chan <= 39)){
			ble_coex.chan_flag |= BIT(ble_scan_chan - 37 + 3);
		}
		
		if(ble_adv){
			ble_coex.coex_flag |= BIT(0);
		}
		
		if(ble_scan){
			ble_coex.coex_flag |= BIT(1);
		}
		
		ble_coex.interval = ble_interval;
		ble_coex.scan_win = ble_scan_win;
		ble_coex.ble_id = BLE_MSG_COEXIST_START;
		ret = wsm_ble_msg_coexist_start(hw_priv, &ble_coex, 0);
	}
	else{
		ble_coex.ble_id = BLE_MSG_COEXIST_STOP;
		ret = wsm_ble_msg_coexist_stop(hw_priv, (struct wsm_ble_msg *)&ble_coex, 0);
	}
	
EXIT:	
	if(ret == 0){
		sprintf(extra,"\nble_coexist success\n");
	}else{
		sprintf(extra,"\nble_coexist fail\n");
	}
	wrqu->data.length = strlen(extra);
	if(pbuffer){
		atbm_kfree(pbuffer);
	}

	return  ret;
}

static int atbm_ioctl_ble_set_adv_data_cmd(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;
	struct wsm_ble_msg_adv_data ble_adv = {0};
	int ret = -1;
	char *pbuffer = NULL;
	char *pTmp = NULL;
	unsigned int rxData;

	if(!(pbuffer = atbm_kmalloc(wrqu->data.length+1, GFP_KERNEL))){
		atbm_printk_err("atbm_kmalloc failed!\n");
		goto EXIT;
	}

	if((ret = copy_from_user(pbuffer, wrqu->data.pointer, wrqu->data.length))){
		atbm_printk_err("copy_from_user failed!\n");
		goto EXIT;
	}

	pTmp = strstr(pbuffer, "mac:");
	if(pTmp){
		pTmp = pTmp + strlen("mac:");
		CmdLine_GetHex(&pTmp, &rxData);
		ble_adv.mac[0] = rxData;
		CmdLine_GetHex(&pTmp, &rxData);
		ble_adv.mac[1] = rxData;
		CmdLine_GetHex(&pTmp, &rxData);
		ble_adv.mac[2] = rxData;
		CmdLine_GetHex(&pTmp, &rxData);
		ble_adv.mac[3] = rxData;
		CmdLine_GetHex(&pTmp, &rxData);
		ble_adv.mac[4] = rxData;
		CmdLine_GetHex(&pTmp, &rxData);
		ble_adv.mac[5] = rxData;
	}
	
	pTmp = strstr(pbuffer, "data:");
	if(pTmp){
		pTmp = pTmp + strlen("data:");
		ble_adv.adv_data_len = strlen(pTmp);
		if(ble_adv.adv_data_len > 31){
			ble_adv.adv_data_len = 31;
		}
		memcpy(ble_adv.adv_data, pTmp, 31);
		ble_adv.ble_id = BLE_MSG_SET_ADV_DATA;
		ret = wsm_ble_msg_set_adv_data(hw_priv, &ble_adv, 0);
	}

EXIT:	
	if(ret == 0){
		sprintf(extra,"\nble set adv data success\n");
	}else{
		sprintf(extra,"\nble set adv data fail\n");
	}
	wrqu->data.length = strlen(extra);
	if(pbuffer){
		atbm_kfree(pbuffer);
	}

	return  ret;
}
#endif

#ifdef CONFIG_ATBM_SUPPORT_REKEY
static int atbm_ioctl_set_rekey(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	int ret = 0;
	bool mgd_lock = false;
	char *ptr  = NULL;
	const char *pos;
	const char *pos_end;
	int len = 0;
	int i = 0;
	int enable = 0;
	printk("%s %d\n",__func__,__LINE__);
	
	if(!ieee80211_sdata_running(sdata)){
		printk("%s %d\n",__func__,__LINE__);
		atbm_printk_wext("%s:%d\n",__func__,__LINE__);
		ret = -ENETDOWN;
		goto exit;
	}

	if(sdata->vif.type != NL80211_IFTYPE_STATION){
		printk("%s %d\n",__func__,__LINE__);
		ret = -EINVAL;
		goto exit;
	}

	mutex_lock(&sdata->u.mgd.mtx);
	
	mgd_lock = true;
	
	if (!sdata->u.mgd.associated){
		printk("%s %d\n",__func__,__LINE__);
		ret = -EINVAL;
		goto exit;
	}

	if(sdata->vif.rekey_set == 0){
		atbm_printk_err("key data not set\n");
		ret = -EINVAL;
		goto exit;
	}
	if(!(ptr = atbm_kmalloc(wrqu->data.length + 1, GFP_KERNEL))){
		printk("%s %d\n",__func__,__LINE__);
		ret = -ENOMEM;
		goto exit;
	}
	
	if((ret = copy_from_user(ptr, wrqu->data.pointer, wrqu->data.length)) != 0){
		ret = -ENOMEM;
		printk("%s %d\n",__func__,__LINE__);
		goto  exit;
	}

	ptr[wrqu->data.length] = 0;
	
	for(i = 0;i<wrqu->data.length;i++){
		if(ptr[i] == ',')
			ptr[i] = ATBM_SPACE;
	}
	
	pos = atbm_skip_space(ptr,wrqu->data.length+1);

	if(pos == NULL){
		printk("%s %d\n",__func__,__LINE__);
		ret = -EINVAL;
		goto exit;
	}

	pos = pos+strlen("set_rekay");

	pos = atbm_skip_space(pos,wrqu->data.length+1-(pos-ptr));

	if(pos == NULL){
		printk("pos == null\n");
		ret = -EINVAL;
		goto exit;
	}

	len = wrqu->data.length + 1 - (pos - ptr);

	if(len <= 0){
		printk("len %d\n",len);
		ret = -EINVAL;
		goto exit;
	}

	pos_end = memchr(pos,ATBM_TAIL,len);
	
	if(pos_end != NULL)
		len = pos_end - pos+1;
	
	ATBM_WEXT_PROCESS_PARAMS(pos,len,enable,atbm_accsii_to_int,false,exit,ret);

	if((enable != 0) && (enable != 1)){
		printk("enable %d\n",enable);
		ret = -EINVAL;
		goto exit;
	}

	drv_set_rekey_data(sdata->local,sdata,enable);
	
exit:
	if(mgd_lock == true)
		mutex_unlock(&sdata->u.mgd.mtx);
	if(ptr)
		atbm_kfree(ptr);
	return ret;
}
#endif
static int atbm_ioctl_common_cmd(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	int ret = 0,cmd_match = 0;
	iwripv_common_cmd_t *cmd = common_cmd;
	unsigned char *ptr = NULL;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	atbm_printk_wext("atbm_ioctl_common_cmd(), length %d\n",wdata->data.length);

	if(!(ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL)))
		return -ENOMEM;
	if((ret = copy_from_user(ptr, wdata->data.pointer, wdata->data.length))){
		atbm_kfree(ptr);
		return -EINVAL;
	}
	
	while(cmd->cmd){
		if(memcmp(ptr, cmd->cmd, cmd->cmd_len) == 0){
			cmd_match = 1;
			break;
		}
		cmd++;
	}
	if(cmd_match)
		ret = cmd->handler(dev, info, wrqu, extra);
	else
		ret = atbm_ioctl_common_help(dev, info, wrqu, extra);
#if 0
	if(memcmp(ptr, "get_rssi", 8) == 0)
		ret = atbm_ioctl_get_rssi(dev, info, wrqu, extra);
	else if(memcmp(ptr, "stations_show", 13) == 0)
		ret = atbm_ioctl_associate_sta_status(dev, info, wrqu, extra);
	else if(memcmp(ptr, "getSigmstarEfuse", 16) == 0)
		ret = atbm_ioctl_get_SIGMSTAR_256BITSEFUSE(dev, info, wrqu, extra);
	else if(memcmp(ptr, "setSigmstarEfuse", 16) == 0)
		ret = atbm_ioctl_set_SIGMSTAR_256BITSEFUSE(dev, info, wrqu, extra);
#ifdef CONFIG_ATBM_IWPRIV_USELESS
	else if(memcmp(ptr, "channel_test_start", 18) == 0)
		ret = atbm_ioctl_channel_test_start(dev, info, wrqu, extra);
#endif
	else if(memcmp(ptr, "get_channel_idle", 16) == 0)
		ret = atbm_ioctl_get_channel_idle(dev, info, wrqu, extra);
	else if(memcmp(ptr, "setEfuse_dcxo", 13) == 0)
		ret = atbm_ioctl_set_efuse(dev, info, wrqu, extra);
	else if(memcmp(ptr, "setEfuse_deltagain", 18) == 0)
		ret = atbm_ioctl_set_efuse(dev, info, wrqu, extra);
	else if(memcmp(ptr, "setEfuse_tjroom", 15) == 0)
		ret = atbm_ioctl_set_efuse(dev, info, wrqu, extra);
	else if(memcmp(ptr, "setEfuse_mac", 12) == 0)
		ret = atbm_ioctl_set_efuse(dev, info, wrqu, extra);
	else if(memcmp(ptr, "getEfuse", 8) == 0)
		ret = atbm_ioctl_get_efuse(dev, info, wrqu, extra);
	else if(memcmp(ptr, "EfusefreeSpace", 14) == 0)
		ret = atbm_ioctl_get_efuse_free_space(dev, info, wrqu, extra);
	else if(memcmp(ptr, "getefusefirst", 13) == 0)
		ret = atbm_ioctl_get_efuse_first(dev, info, wrqu, extra);
#ifdef CONFIG_ATBM_IWPRIV_USELESS
	else if(memcmp(ptr, "freqoffset", 10) == 0)
		ret = atbm_ioctl_freqoffset(dev, info, wrqu, extra);
#endif
	else if(memcmp(ptr, "singletone", 10) == 0)
		ret = atbm_ioctl_send_singleTone(dev, info, wrqu, extra);
#ifdef CONFIG_ATBM_IWPRIV_USELESS
	else if(memcmp(ptr, "duty_ratio", 10) == 0)
		ret = atbm_ioctl_set_duty_ratio(dev, info, wrqu, extra);
#endif
#ifdef CONFIG_ATBM_SUPPORT_AP_CONFIG
	else if(memcmp(ptr, "ap_conf", 7) == 0)
		ret = atbm_ioctl_set_ap_conf(dev, info, wrqu, extra);
#endif
#ifdef CONFIG_ATBM_MONITOR_SPECIAL_MAC
	else if(memcmp(ptr, "monitor_mac", 11) == 0)
		ret = atbm_ioctl_rx_monitor_mac(dev, info, wrqu, extra);
	else if(memcmp(ptr, "monitor_status", 14) == 0)
		ret = atbm_ioctl_rx_monitor_mac_status(dev, info, wrqu, extra);
#endif
#ifdef CONFIG_IEEE80211_SPECIAL_FILTER
	else if(memcmp(ptr,"filter_frame",12) == 0){
		ret = atbm_ioctl_rx_filter_frame(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"filter_ie",9) == 0){
		ret = atbm_ioctl_rx_filter_ie(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"filter_clear",12) == 0){
		ret = atbm_ioctl_rx_filter_clear(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"filter_show",11) == 0){
		ret = atbm_ioctl_rx_filter_show(dev, info, wrqu, extra);
	}
#endif
#ifdef HIDDEN_SSID
	else if(memcmp(ptr, "ap_hide_ssid", 12) == 0){
		ret = atbm_ioctl_set_hidden_ssid(dev, info, wrqu, extra);
	}
#endif
	else if(memcmp(ptr,"get_last_mac",12) == 0){
		ret = atbm_ioctl_get_Last_mac(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"get_first_mac",13) == 0){
		ret = atbm_ioctl_get_First_mac(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"get_tjroom",10) == 0){
		ret = atbm_ioctl_get_Tjroom(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"set_cali_flag",13) == 0){
		ret = atbm_ioctl_set_calibrate_flag(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"set_all_efuse",13) == 0){
		ret = atbm_ioctl_set_all_efuse(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"stations_show",13) == 0){
		ret = atbm_ioctl_associate_sta_status(dev, info, wrqu, extra);
	}
#ifdef ATBM_PRIVATE_IE
	else if(memcmp(ptr,"ipc_reset",9) == 0){
		atbm_ioctl_ie_ipc_clear_insert_data(dev, info, wrqu, extra);
	}
#endif

//#ifdef ATBM_PS_MODE
	else if(memcmp(ptr,"power_save",10) == 0){

		atbm_set_power_save_mode(dev, info, wrqu, extra);
	}
#ifdef JA_SUBTYPE_OXF0
else if(memcmp(ptr,"subtype",7) == 0){
		ret = atbm_ioctl_subtype(dev, info, wrqu, extra);
	}
#endif
	else if(memcmp(ptr,"gpio_conf",9) == 0){
		ret = atbm_ioctl_gpio_config(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"gpio_out",8) == 0){
		ret = atbm_ioctl_gpio_output(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"edca_params",11) == 0){
		ret = atbm_ioctl_edca_params(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"get_edca_params",15) == 0){
		ret = atbm_ioctl_get_edca_params(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"txpower_status",14) == 0){
		ret = atbm_ioctl_get_txposer_status(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"settxpower_byfile",17) == 0){
		ret = atbm_ioctl_set_txpwr_by_file(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"set_rate_power",14) == 0){
		ret = atbm_ioctl_set_rate_txpwr_by_file(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"set_frame_rate",14) == 0){
		ret = atbm_ioctl_set_management_frame_rate(dev, info, wrqu, extra);
	}else if(memcmp(ptr,"get_maxrate",11) == 0){
		ret = atbm_ioctl_get_cur_max_rate(dev, info, wrqu, extra);
	}else if (memcmp(ptr,"get_work_channel",16) == 0){
		ret = atbm_ioctl_get_work_channel(dev, info, wrqu, extra);
	}else
		ret = -1;
#endif

	atbm_printk_err("extra:%s\n",extra);
	if(ret < 0)
		atbm_printk_err("atbm_ioctl_common_cmd(), error %s\n", ptr);
	atbm_kfree(ptr);
	
	return ret;
}


#ifdef CONFIG_ATBM_STA_LISTEN
static int atbm_ioctl_set_sta_channel(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	unsigned char *ptr = NULL;
	const unsigned char *pos = NULL;
	const unsigned char *pos_end = NULL;
	int len = 0;
	union iwreq_data *wdata = (union iwreq_data *)wrqu;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	int channel = 0;
	int ret = 0;
	
	if(wdata->data.length <= 0){
		ret =  -EINVAL;
		goto exit;
	}
	ptr = (char *)atbm_kzalloc(wdata->data.length+1, GFP_KERNEL);

	if(ptr == NULL){
		ret = -ENOMEM;
		goto exit;
	}

	if(copy_from_user(ptr, wdata->data.pointer, wdata->data.length) != 0){
		ret = -EINVAL;
		goto exit;
	}
	
	atbm_printk_wext("%s:len(%d)(%s)\n",__func__,wdata->data.length,ptr);
	/*
	*skip space
	*/

	pos = atbm_skip_space(ptr,wdata->data.length);

	if(pos == NULL){		
		ret = -EINVAL;
		goto exit;
	}
	
	len = (int)(wdata->data.length - (pos-ptr));

	pos_end = memchr(pos,ATBM_TAIL,len);

	if(pos_end != NULL)
		len = pos_end - pos;
	
	if(len >2){
		ret = -EINVAL;
		goto exit;
	}
	
	if(atbm_accsii_to_int(pos,len,&channel) == false){		
		ret = -EINVAL;
		goto exit;
	}
	ret = ieee80211_set_sta_channel(sdata,channel);
	
exit:
	if(ptr)
		atbm_kfree(ptr);
	return ret;
}

#endif
static int atbm_ioctl_rx_statistic(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	u32 rx_status[3] = {0,0,0};
	u8 *status = NULL;
	int len = 0;
	int ret = 0;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct atbm_common *hw_priv=local->hw.priv;

	if(ETF_bStartRx == 0){
		atbm_printk_wext("%s:start rx not running\n",__func__);
		ret = -EOPNOTSUPP;
		goto exit;
	}

	ret = wsm_read_shmem(hw_priv,(u32)RX_STATUS_ADDR,rx_status,sizeof(rx_status));

	if(ret != 0){
		ret = -EINVAL;
		goto exit;
	}

	status = atbm_kzalloc(512,GFP_KERNEL);
	
	if(status == NULL){
		atbm_printk_wext("%s:atbm_kzalloc err\n",__func__);
		ret = -ENOMEM;
		goto exit;
	}

	len = scnprintf(status,512,"rxSuccess:%d, FcsErr:%d, PlcpErr:%d\n",
	rx_status[0]-rx_status[1],rx_status[1],rx_status[2]);

	if(extra){
		memcpy(extra,status,len);	
		wrqu->data.length = strlen(status) + 1;
	}
exit:
	if(status)
		atbm_kfree(status);

	return ret;
}
const iw_handler atbm_private_handler[]={
#ifdef CONFIG_ATBM_PRIV_HELP
	[0] = (iw_handler)atbm_ioctl_command_help,
#endif
#ifdef ATBM_SUPPORT_SMARTCONFIG
	[1] = (iw_handler)atbm_ioctl_smartconfig_start,	
#endif
	[2] = (iw_handler)atbm_ioctl_start_tx,
	[3] = (iw_handler)atbm_ioctl_stop_tx,
	[4] = (iw_handler)atbm_ioctl_start_rx,
	[5] = (iw_handler)atbm_ioctl_stop_rx,
	[6] = (iw_handler)atbm_ioctl_fwdbg,
	[7] = (iw_handler)atbm_ioctl_rx_statistic,
	[8] = (iw_handler)atbm_ioctl_fwcmd,
#ifdef ATBM_SUPPORT_SMARTCONFIG
	[10] = (iw_handler)atbm_ioctl_smartconfig_stop,
#endif
	[11] = (iw_handler)atbm_ioctl_common_cmd,
	[12] = (iw_handler)atbm_ioctl_ctl_gi,
	[13] = (iw_handler)atbm_ioctl_getmac,
#ifdef CONFIG_ATBM_START_WOL_TEST
	[14] = (iw_handler)atbm_ioctl_start_wol,
#endif
#ifdef CONFIG_ATBM_IWPRIV_USELESS
	[15] = (iw_handler)atbm_ioctl_get_rx_stats,
#endif
	[16] = (iw_handler)atbm_ioctl_set_rts,
#ifdef ATBM_SUPPORT_SMARTCONFIG
	[17] = (iw_handler)atbm_ioctl_smartconfig_start_v2,
#endif
	[18] = (iw_handler)atbm_ioctl_etf_result_get,
#ifdef ATBM_SUPPORT_SMARTCONFIG
	[19] = (iw_handler)atbm_ioctl_smartconfig_stop_v2,
#endif
#ifdef ATBM_PRIVATE_IE
	/*Private IE for Scan*/
	[20] = (iw_handler)atbm_ioctl_ie_insert_user_data,
	[21] = (iw_handler)atbm_ioctl_ie_get_user_data,
	[22] = (iw_handler)atbm_ioctl_ie_send_msg,
	[23] = (iw_handler)atbm_ioctl_ie_recv_msg,
//	[25] = (iw_handler)atbm_ioctl_get_wifi_state,
	[26] = (iw_handler)atbm_ioctl_set_freq,
	[27] = (iw_handler)atbm_ioctl_best_ch_scan,
	[29] = (iw_handler)atbm_ioctl_get_rate,
	[30] = (iw_handler)atbm_ioctl_set_txpw,
#ifdef CONFIG_ATBM_STA_LISTEN
	[31] = (iw_handler)atbm_ioctl_set_sta_channel,
#endif
#else
//	[20] = (iw_handler)atbm_ioctl_get_wifi_state,
	[21] = (iw_handler)atbm_ioctl_best_ch_scan,
	[22] = (iw_handler)atbm_ioctl_set_txpw,
	[23] = (iw_handler)atbm_ioctl_get_rate,
	[24] = (iw_handler)atbm_ioctl_set_freq,
#ifdef CONFIG_ATBM_STA_LISTEN
	[25] = (iw_handler)atbm_ioctl_set_sta_channel,
#endif
#endif	
};


void register_wext_common(struct ieee80211_local *local){

#ifdef CONFIG_WIRELESS_EXT
#ifdef CONFIG_CFG80211_WEXT
	if(local->hw.wiphy->wext)
	{
	        atbm_handlers_def.standard = local->hw.wiphy->wext->standard;
	        atbm_handlers_def.num_standard = local->hw.wiphy->wext->num_standard;
		#if WIRELESS_EXT >= 17
	        atbm_handlers_def.get_wireless_stats = local->hw.wiphy->wext->get_wireless_stats;
		#endif
#endif
		#ifdef CONFIG_WEXT_PRIV
			atbm_handlers_def.num_private = sizeof(atbm_private_handler)/sizeof(atbm_private_handler[0]) ;
			atbm_handlers_def.private = atbm_private_handler ;
			atbm_handlers_def.num_private_args = sizeof(atbm_privtab)/sizeof(atbm_privtab[0]);
			atbm_handlers_def.private_args = (struct iw_priv_args *)atbm_privtab;
		#endif
#ifdef CONFIG_CFG80211_WEXT
	}
#endif
#endif

}

int atbm_ioctl_etf_result_get(struct net_device *dev, struct iw_request_info *info, union iwreq_data  *wrqu, char *extra)
{
	int ret = 0;
	u8 chipid = 0;
	u8 buff[512];

	chipid = chipversion;
	memset(buff, 0, 512);
#ifdef ATBM_PRODUCT_TEST_USE_FEATURE_ID
	sprintf(buff, "%d%dcfo:%d,txevm:%d,rxevm:%d,dcxo:%d,txrssi:%d,rxrssi:%d,result:%d (0:OK; -1:FreqOffset Error; -2:efuse hard error;"
		" -3:efuse no written; -4:efuse anaysis failed; -5:efuse full; -6:efuse version change; -7:rx null)",
	gRxs_s.valid,
	chipid,
	gRxs_s.Cfo,
	gRxs_s.txevm,
	gRxs_s.evm,
	gRxs_s.dcxo,
	gRxs_s.TxRSSI,
	gRxs_s.RxRSSI,
	gRxs_s.result
	);
#else
	//cvte 6022 use older version atbm_iw tool
	sprintf(buff, "%dcfo:%d,txevm:%d,rxevm:%d,dcxo:%d,txrssi:%d,rxrssi:%d,result:%d,share:%d (0:OK; -1:FreqOffset Error; -2:efuse hard error;"
		" -3:efuse no written; -4:efuse anaysis failed; -5:efuse full; -6:efuse version change; -7:rx null)",
	gRxs_s.valid,
	gRxs_s.Cfo,
	gRxs_s.txevm,
	gRxs_s.evm,
	gRxs_s.dcxo,
	gRxs_s.TxRSSI,
	gRxs_s.RxRSSI,
	gRxs_s.result,
	etf_config.chip_crystal_type
	);
#endif
	if((ret = copy_to_user(wrqu->data.pointer, buff, strlen(buff))) != 0){
		return -EINVAL;
	}

	return ret;
}


#endif //CONFIG_WIRELESS_EXT

extern int atbm_direct_read_reg_32(struct atbm_common *hw_priv, u32 addr, u32 *val);
extern int atbm_direct_write_reg_32(struct atbm_common *hw_priv, u32 addr, u32 val);










static int etf_rx_status_get(struct atbm_common *hw_priv)
{
	int ret = 0;
	int i = 0;
	struct rxstatus rxs; 
	char *extra = NULL;
	struct atbm_vif *vif;

	atbm_printk_debug("[%s]:%d\n", __func__, __LINE__);
	if(!(extra = atbm_kmalloc(sizeof(struct rxstatus), GFP_KERNEL)))
	{
		atbm_printk_err("%s:malloc failed\n", __func__);
		return -ENOMEM;	
	}

	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			ret = wsm_read_mib(hw_priv, WSM_MIB_ID_GET_ETF_RX_STATS,
				extra, sizeof(struct rxstatus), vif->if_id);
			break;
		}
	}
	memcpy(&rxs, extra, sizeof(struct rxstatus));

	if(rxs.probcnt == 0)
	{
		atbm_printk_wext("%s:rxs.probcnt == 0\n", __func__);
		goto out;
	}

	if(ret == 0)
	{
		gRxs_s.evm				= rxs.evm/rxs.probcnt;
		gRxs_s.RxRSSI			= (s16)N_BIT_TO_SIGNED_32BIT(rxs.RSSI, 8)*4;
		gRxs_s.RxRSSI += etf_config.cableloss;	
	}
	else
	{
		atbm_printk_wext("%s:get rx status failed\n", __func__);
	}
out:
	if(extra)
		atbm_kfree(extra);
	return ret;

}

#ifdef CONFIG_ATBM_IWPRIV_USELESS
static int getFreqoffsetHz(struct atbm_common *hw_priv, struct rxstatus_signed *rxs_s)
{
	struct rxstatus rxs; 
	int FreqOffsetHz;
	char *extra = NULL;
	int i = 0;
	long lcfo = 0;
	struct atbm_vif *vif;
	if(!(extra = atbm_kmalloc(16, GFP_KERNEL)))
	return -ENOMEM;

	atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_read_mib(hw_priv, WSM_MIB_ID_GET_ETF_RX_STATS,
						extra, 16, vif->if_id));
					break;
				}
			}
	memcpy(&rxs, extra, sizeof(struct rxstatus));
	
	atbm_kfree(extra);
	
#if 0
	printk("Cfo:%d,RSSI:%d,evm:%d,GainImb:%d, PhaseImb:%d, FreqOffsetHz:%d\n",
	rxs.Cfo,
	rxs.RSSI,
	rxs.evm,
	rxs.GainImb,
	rxs.PhaseImb,
	FreqOffsetHz
	);
#endif
	
	rxs_s->GainImb		= (s16)N_BIT_TO_SIGNED_32BIT(rxs.GainImb, 10);
	rxs_s->PhaseImb		= (s16)N_BIT_TO_SIGNED_32BIT(rxs.PhaseImb, 10);
	rxs_s->Cfo			= (s16)N_BIT_TO_SIGNED_32BIT(rxs.Cfo, 16);
	rxs_s->evm			= rxs.evm;
	rxs_s->RxRSSI			= (s8)N_BIT_TO_SIGNED_32BIT(rxs.RSSI, 8);

	lcfo = rxs_s->Cfo;
	FreqOffsetHz = (int)(((lcfo*12207)/10)*(-1));

	atbm_printk_wext("Host Rx: Cfo:%d,RxRSSI:%d,evm:%d,GainImb:%d, PhaseImb:%d, FreqOffsetHz:%d\n",
	rxs_s->Cfo,
	rxs_s->RxRSSI,
	rxs_s->evm,
	rxs_s->GainImb,
	rxs_s->PhaseImb,
	FreqOffsetHz
	);
	

	return FreqOffsetHz;
}

static int _getMaxRssiInd(struct rxstatus_signed rxs_arr[], int cnt)
{
	int i=0;
	struct rxstatus_signed *rxsMax;
	int cntMax = 0;

	rxsMax = &rxs_arr[0];

	atbm_printk_wext("_getMaxRssiInd()\n");
	
	for(i=1; i<cnt; i++)
	{
#if 0
		printk("#Cfo:%d,RxRSSI:%d,evm:%d,GainImb:%d, PhaseImb:%d\n",
		rxs_arr[i].Cfo,
		rxs_arr[i].RxRSSI,
		rxs_arr[i].evm,
		rxs_arr[i].GainImb,
		rxs_arr[i].PhaseImb
		);
#endif
		if(rxs_arr[i].RxRSSI >= rxsMax->RxRSSI)
		{
			if(rxs_arr[i].evm <= rxsMax->evm)
			{
				rxsMax = &rxs_arr[i];
				cntMax = i;
			}
		}
	}

	atbm_printk_wext("Host Rx: MaxRssi[%d]#Cfo:%d,RxRSSI:%d,evm:%d,GainImb:%d, PhaseImb:%d\n",
	cntMax,
	rxsMax->Cfo,
	rxsMax->RxRSSI,
	rxsMax->evm,
	rxsMax->GainImb,
	rxsMax->PhaseImb
	);

	return cntMax;
}
static int Test_FreqOffset(struct atbm_common *hw_priv, u32 *dcxo, int *pfreqErrorHz, struct rxstatus_signed *rxs_s, int channel)
{
	u8 CodeValue;
	u8 CodeValuebak;
	u8 CodeStart,CodeEnd;
	int b_fail =1;
	int freqErrorHz = 0;
	int targetFreqOffset = TARGET_FREQOFFSET_HZ;
	struct atbm_vif *vif;

	char cmd[64];
	int i = 0;
	int itmp=0;
	int index=0;
	u8 ucDbgPrintOpenFlag = 1;
	struct rxstatus_signed rxs_arr[FREQ_CNT];
	int freqErrorHz_arr[FREQ_CNT];
	
	CodeValue = DCXOCodeRead(hw_priv);	
	DCXOCodeWrite(hw_priv,CodeValue);	

	if(ETF_bStartTx || ETF_bStartRx){
		atbm_printk_err("Error! already start_tx, please stop_tx first!\n");
		return b_fail;
	}


	//./iwpriv wlan0 fwdbg 1
	ucDbgPrintOpenFlag = 1;
	atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
					break;
				}
			}


	//start DUT Rx

	sprintf(cmd,  "monitor 1,%d,0",channel);
	
	atbm_printk_wext("start DUT Rx CMD:%s\n", cmd);
	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			ETF_bStartRx = 1;
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,
				cmd, strlen(cmd) + 10, vif->if_id));
			break;
		}
	}

	CodeStart = DCXO_CODE_MINI;
	CodeEnd = DCXO_CODE_MAX;

	msleep(50);
	atbm_printk_wext("CodeValue default:%d\n",CodeValue);
	while(1)
	{
		CodeValuebak = CodeValue;
		for (itmp=0;itmp<FREQ_CNT;itmp++)
		{
			msleep(10);
			freqErrorHz_arr[itmp] = getFreqoffsetHz(hw_priv, &rxs_arr[itmp]);
		}
		index = _getMaxRssiInd(rxs_arr,FREQ_CNT);
		freqErrorHz = freqErrorHz_arr[index];
		memcpy(rxs_s, &rxs_arr[index], sizeof(struct rxstatus_signed));

		if (freqErrorHz >= targetFreqOffset)
		{
			CodeStart = CodeValue;
			CodeValue += (CodeEnd - CodeStart)/2;
			CodeStart = CodeValuebak;

			atbm_printk_wext("freqErrorHz:%d >= targetFreqOffset%d,CodeValue%d CodeEnd[%d]. CodeStart[%d]\n",
				freqErrorHz,targetFreqOffset,	CodeValue,CodeEnd , CodeStart);
			
			DCXOCodeWrite(hw_priv,CodeValue);
			if (CodeValue >= 0xff)
			{
				break;
			}
		}
		else if ((int)freqErrorHz <= -targetFreqOffset)
		{
			CodeEnd = CodeValue;
			CodeValue -= (CodeEnd - CodeStart)/2;
			CodeEnd = CodeValuebak;
			
			atbm_printk_wext("freqErrorHz:%d <= targetFreqOffset%d,CodeValue%d CodeEnd[%d]. CodeStart[%d]\n",
				freqErrorHz,targetFreqOffset,	CodeValue,CodeEnd , CodeStart);
			
			DCXOCodeWrite(hw_priv,CodeValue);
			if (CodeValue < 0x01)
			{
				break;
			}
			if (0x01 == CodeEnd)
			{
				break;
			}
		}
		else
		{
			atbm_printk_wext("[PASS]freqErrorKHz[%d] CodeValue[%d]!\n",freqErrorHz/1000,CodeValue);
			b_fail = 0;
			*dcxo = CodeValue;
			*pfreqErrorHz = freqErrorHz;
			break;
		}

		if(CodeValue == CodeValuebak)
		{
			break;
		}

	}


	mutex_lock(&hw_priv->conf_mutex);
	memset(cmd,0,sizeof(cmd));
	memcpy(cmd, "monitor 0", 9);
	//stop DUT Rx
#if 1	
	atbm_printk_wext("stop DUT Rx CMD:%s\n", cmd);
	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			ETF_bStartRx = 0;
			WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,
				cmd, strlen(cmd) + 10, vif->if_id));
			break;
		}
	}
	mutex_unlock(&hw_priv->conf_mutex);

	//./iwpriv wlan0 fwdbg 1
	ucDbgPrintOpenFlag = 0;
	atbm_for_each_vif(hw_priv,vif,i){
				if (vif != NULL)
				{
					WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id));
					break;
				}
			}

	
#endif
	return b_fail;
}
#endif

/*
return value:
	0: success.
	1:freq offset not ok yet,need next test
	2:dcxo cal max
	3.dcxo cal min
*/
static int Test_FreqOffset_v2(struct atbm_common *hw_priv, u32 *dcxo, int *pfreqErrorHz)
{
	u8 CodeValue,CodeValuebak;
	int b_fail =1;
	int freqErrorHz = 0;
	int targetFreqOffset = TARGET_FREQOFFSET_HZ;
	static int first_cal = 0;

	if(etf_config.freq_ppm != 0)
		targetFreqOffset = etf_config.freq_ppm;

	if((etf_config.default_dcxo != 0)
		&& (etf_config.default_dcxo >= 0)
		&& (etf_config.default_dcxo <= 127)
		&& (first_cal == 0))
	{
		first_cal = 1;
		atbm_printk_debug("wirte default dcxo when calibration firstly\n");
		CodeValue = etf_config.default_dcxo;
		DCXOCodeWrite(hw_priv,CodeValue);	
	}
	else
	{
		CodeValue = DCXOCodeRead(hw_priv);	
		DCXOCodeWrite(hw_priv,CodeValue);	
	}


	atbm_printk_always("CodeValue default:%d\n",CodeValue);

	
	CodeValuebak = CodeValue;

	freqErrorHz = gRxs_s.Cfo;

	//no freqOffset Calibration,
	if(etf_config.noFfreqCaliFalg == 1)
	{
		atbm_printk_always("targetFreqOffset[%d~%d]Hz\n", -targetFreqOffset,targetFreqOffset);
		if ((freqErrorHz > targetFreqOffset) || (freqErrorHz < -targetFreqOffset))
		{
			atbm_printk_always("fail freqError[%d]Hz dcxo[%d]!\n",freqErrorHz,CodeValue);
			b_fail = 2;
		}
		else
		{
			atbm_printk_always("pass freqError[%d]Hz dcxo[%d]!\n",freqErrorHz,CodeValue);
			b_fail = 0;
		}
		*dcxo = CodeValue;
		*pfreqErrorHz = freqErrorHz;

		return b_fail;
	}

	if (freqErrorHz > targetFreqOffset)
	{
		CodeStart = CodeValue;
		CodeValue += (CodeEnd - CodeStart)/2;
		CodeStart = CodeValuebak;

		atbm_printk_always("freqErrorHz[%d] > targetFreqOffset[%d],CodeValue[%d] ,CodeStart[%d], CodeEnd[%d] . \n",
			freqErrorHz,targetFreqOffset,	CodeValue, CodeStart ,CodeEnd );
		
		DCXOCodeWrite(hw_priv,CodeValue);

		b_fail = 1;
		if (CodeValue >= 126)
		{
			b_fail = 2;
		}
		if (CodeValue >= 0xff)
		{
			b_fail = 2;
		}
	}
	else if ((int)freqErrorHz < -targetFreqOffset)
	{
		CodeEnd = CodeValue;
		CodeValue -= (CodeEnd - CodeStart)/2;
		CodeEnd = CodeValuebak;

		atbm_printk_always("freqErrorHz[%d] < targetFreqOffset[%d],CodeValue[%d] ,CodeStart[%d], CodeEnd[%d] . \n",
			freqErrorHz,targetFreqOffset,	CodeValue, CodeStart ,CodeEnd );
		DCXOCodeWrite(hw_priv,CodeValue);

		b_fail = 1;
		
		if (CodeValue <= 2)
		{
			b_fail = 3;
		}
		if (0x01 == CodeEnd)
		{
			b_fail = 3;
		}
	}
	else
	{
		first_cal = 0;
		atbm_printk_always("[dcxo PASS]freqErrorKHz[%d] CodeValue[%d]!\n",freqErrorHz/1000,CodeValue);
		b_fail = 0;
		*dcxo = CodeValue;
		*pfreqErrorHz = freqErrorHz;
	}

	if((CodeEnd == CodeStart) ||
		((CodeEnd - CodeStart) == 1) ||
		((CodeEnd - CodeStart) == -1))
	{
		atbm_printk_always("CodeValue[%d] ,CodeStart[%d], CodeEnd[%d] . \n",CodeValue, CodeStart ,CodeEnd);
		b_fail = 2;
	}

	
	return b_fail;

}


static int atbm_freqoffset_save_efuse(struct atbm_common *hw_priv,struct rxstatus_signed rxs_s,u32 dcxo)
{
	int ret = 0;
	int iResult=0;
	//struct atbm_vif *vif;
	struct efuse_headr efuse_d,efuse_bak;
	
	
	//u8 buff[512];

	memset(&efuse_d,0,sizeof(struct efuse_headr));
	memset(&efuse_bak,0,sizeof(struct efuse_headr));

	

	//tmp = DCXOCodeRead(hw_priv);printk("tmp %d\n"tmp);	
	if(ucWriteEfuseFlag)
	{
		atbm_printk_always("ucWriteEfuseFlag :%d\n",ucWriteEfuseFlag);
		wsm_get_efuse_data(hw_priv,(void *)&efuse_d,sizeof(struct efuse_headr));

		if(efuse_d.version == 0)
		{
			//The first time efuse is written,all the data should be written, 
			//The production test only modifies part of the value, so efuse cannot be written.
			iResult = -3;
			goto FEEQ_ERR;
		}

		if(efuse_d.dcxo_trim == dcxo) // old dcxo equal new dcxo, no need to write efuse.
		{
			atbm_printk_always(" old dcxo equal new dcxo, no need to write efuse.\n");
			iResult = 0;
			goto FEEQ_ERR;
		}
		efuse_d.dcxo_trim = dcxo;
		//write amc address
		if(etf_config.writemacflag == 1){
			memcpy(efuse_d.mac, etf_config.writemac, 6);
		}
		/*
		*LMC_STATUS_CODE__EFUSE_VERSION_CHANGE	failed because efuse version change  
		*LMC_STATUS_CODE__EFUSE_FIRST_WRITE, 		failed because efuse by first write   
		*LMC_STATUS_CODE__EFUSE_PARSE_FAILED,		failed because efuse data wrong, cannot be parase
		*LMC_STATUS_CODE__EFUSE_FULL,				failed because efuse have be writen full
		*/
		ret = wsm_efuse_change_data_cmd(hw_priv, &efuse_d,0);
		if (ret == LMC_STATUS_CODE__EFUSE_FIRST_WRITE)
		{
			iResult = -3;
		}else if (ret == LMC_STATUS_CODE__EFUSE_PARSE_FAILED)
		{
			iResult = -4;
		}else if (ret == LMC_STATUS_CODE__EFUSE_FULL)
		{
			iResult = -5;
		}else if (ret == LMC_STATUS_CODE__EFUSE_VERSION_CHANGE)
		{
			iResult = -6;
		}else
		{
			iResult = 0;
		}
		frame_hexdump("efuse_d", (u8 *)&efuse_d, sizeof(struct efuse_headr));
		wsm_get_efuse_data(hw_priv,(void *)&efuse_bak, sizeof(struct efuse_headr));
		frame_hexdump("efuse_bak", (u8 *)&efuse_bak, sizeof(struct efuse_headr));
		
		if(memcmp((void *)&efuse_bak,(void *)&efuse_d, sizeof(struct efuse_headr)) !=0)
		{
			iResult = -2;
		}else
		{
			iResult = 0;
		}
		
	}

	
FEEQ_ERR:	
	
	/*sprintf(buff, "cfo:%d,evm:%d,gainImb:%d, phaseImb:%d,dcxo:%d,result:%d (0:OK; -1:FreqOffset Error; -2:efuse hard error;"
		" -3:efuse no written; -4:efuse anaysis failed; -5:efuse full; -6:efuse version change)",
	rxs_s.Cfo,
	rxs_s.evm,
	rxs_s.GainImb,
	rxs_s.PhaseImb,
	dcxo,
	iResult
	);*/

	//if((ret = copy_to_user(wrqu->data.pointer, buff, strlen(buff))) != 0){
	//	return -EINVAL;
	//}

	return iResult;
}


/**************************************************************************
**
** NAME         LMC_FM_GetATBMIe
**
** PARAMETERS:  pElements  -> Pointer to the Ie list
**              Length     -> Size of the Ie List
**              
** RETURNS:     Pointer to element if found or 0 otherwise.
**
** DESCRIPTION  Searches for ATBM test element  from a given IE list.
** 
**************************************************************************/
static u8* LMC_FM_GetATBMIe(u8 *pElements,u16 Length)
{
  u8     ATBMIeOui[3]   = ATBM_OUI	;
  
  struct ATBM_TEST_IE  *Atbm_Ie;
	//dump_mem(pElements,Length);

   if(Length > sizeof(struct ATBM_TEST_IE)){
		pElements += Length-sizeof(struct ATBM_TEST_IE);
		Atbm_Ie =(struct ATBM_TEST_IE  *) pElements;
		/*
		DBG_Printf("Atbm_Ie->oui_type %x,Atbm_Ie->oui %x %x,size %x\n",
			Atbm_Ie->oui_type,
			Atbm_Ie->oui[2],
			ATBMIeOui[2],
			sizeof(struct ATBM_TEST_IE));
		
		dump_mem(pElements,16);*/

		 if(pElements[0]== D11_WIFI_ELT_ID){
			 if((memcmp(Atbm_Ie->oui,ATBMIeOui,3)==0)&&
			 	(Atbm_Ie->oui_type== WIFI_ATBM_IE_OUI_TYPE) ){
				return pElements;
			}
		 }
   }

  return (u8 *)NULL  ;
}//end LMC_FM_GetP2PIe()

static int etf_v2_compare_test_result(void)
{	
	if((etf_config.txpwrmax == 0) && (etf_config.txpwrmin == 0))
	{
		etf_config.txpwrmax = 65536;
		if((efuse_data_etf.specific & 0x1))//outerPA(6038)
		{


			etf_config.txpwrmin = -60+etf_config.cableloss;	
		}
		else
		{
			etf_config.txpwrmin = -84+etf_config.cableloss;	
		}
		atbm_printk_wext("Use default Txrssimin threshold[-84+120]:%d\n", etf_config.txpwrmin);
	}

	if((etf_config.txevmthreshold != 0) && (gRxs_s.txevm > etf_config.txevmthreshold))
	{
		atbm_printk_err("Test txevm:%d > threshold txevm:%d\n", gRxs_s.txevm, etf_config.txevmthreshold);
		return 1;
	}

	if((etf_config.rxevmthreshold != 0) && (gRxs_s.evm > etf_config.rxevmthreshold))
	{
		atbm_printk_err("Test rxevm:%d > threshold rxevm:%d\n", gRxs_s.evm, etf_config.rxevmthreshold);
		return 2;
	}
	if((etf_config.txpwrmax != 0) && (etf_config.txpwrmin != 0) &&
		((gRxs_s.TxRSSI > etf_config.txpwrmax) ||
		(gRxs_s.TxRSSI < etf_config.txpwrmin)))
	{
		atbm_printk_err("Test txpower:%d,txpowermax:%d, txpowermin:%d\n",
			gRxs_s.TxRSSI, etf_config.txpwrmax, etf_config.txpwrmin);
		return 3;
	}
	if((etf_config.rxpwrmax != 0) && (etf_config.rxpwrmin!= 0) &&
		((gRxs_s.RxRSSI > etf_config.rxpwrmax) ||
		(gRxs_s.RxRSSI < etf_config.rxpwrmin)))
	{
		atbm_printk_err("Test rxpower:%d,rxpowermax:%d, rxpowermin:%d\n",
			gRxs_s.RxRSSI, etf_config.rxpwrmax, etf_config.rxpwrmin);
		return 4;
	}

	return 0;
}

int etf_v2_scan_end(struct atbm_common *hw_priv, struct ieee80211_vif *vif )
{
	int ret = 0;
	int result = 0;//(0:OK; -1:FreqOffset Error; -2:Write efuse Failed;-3:efuse not write;-4:rx fail)
	u32 dcxo = 0;
	int freqErrorHz;
	int ErrCode = -1;

#ifdef CONFIG_ATBM_ETF_OLD
	if(hw_priv->etf_test_v2 == 0)
	{
		atbm_test_rx_cnt = 0;
	}
	else
#endif
	{
		ret = etf_rx_status_get(hw_priv);
		if(ret != 0)
		{
			atbm_test_rx_cnt = 0;
			atbm_printk_wext("%s:etf_rx_status_get failed,ret:%d\n", __func__, ret);
		}
	}
	msleep(10);

	if(atbm_test_rx_cnt <= 5){
		memset(&gRxs_s, 0, sizeof(struct rxstatus_signed));
		//up(&hw_priv->scan.lock);
		//hw_priv->etf_test_v2 = 0;
		atbm_printk_always("etf rx data[%d] less than 5 packet\n",atbm_test_rx_cnt);
		ErrCode = -7;
		goto Error;
	}
	
	gRxs_s.TxRSSI += etf_config.cableloss;
	gRxs_s.txevm = txevm_total/atbm_test_rx_cnt;
	
	atbm_printk_always("Average: Cfo:%d,TxRSSI:%d,RxRSSI:%d,txevm:%d,rxevm:%d\n",	
	gRxs_s.Cfo,
	gRxs_s.TxRSSI,
	gRxs_s.RxRSSI,
	gRxs_s.txevm,
	gRxs_s.evm
	);
	
#if 0//CONFIG_ATBM_PRODUCT_TEST_NO_UART
	int efuse_remainbit = 0;

	efuse_remainbit = wsm_get_efuse_status(hw_priv, vif);
	printk("efuse remain bit:%d\n", efuse_remainbit);

	if(efuse_remainbit < 8)
	{		
		printk("##efuse is full,do not calibrte FreqOffset\n##");
		dcxo = efuse_data_etf.dcxo_trim;
		if(etf_config.freq_ppm != 0)
		{
			if((gRxs_s.Cfo > -etf_config.freq_ppm) &&
				(gRxs_s.Cfo < etf_config.freq_ppm))
			{
				printk("#1#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, etf_config.freq_ppm);
				goto success;
			}
			else
			{
				printk("#1#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, etf_config.freq_ppm);
				goto Error;
			}
		}
		else
		{
			if((gRxs_s.Cfo > -TARGET_FREQOFFSET_HZ) &&
				(gRxs_s.Cfo < TARGET_FREQOFFSET_HZ))
			{
				printk("#2#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, TARGET_FREQOFFSET_HZ);
				goto success;
			}
			else
			{
				printk("#2#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, TARGET_FREQOFFSET_HZ);
				goto Error;
			}
		}
	}
#endif
	if(etf_config.chip_crystal_type != 2)
	{
		if(etf_config.freq_ppm != 0)
			result = Test_FreqOffset_v2(hw_priv,&dcxo,&freqErrorHz);
		else
		{
			dcxo = efuse_data_etf.dcxo_trim;
			atbm_printk_always("Not need to Calibrate FreqOffset\n");
			result = 0;
			goto success;
		}
	}
	else
	{
		dcxo = efuse_data_etf.dcxo_trim;
		atbm_printk_always("Crystal,Not need to Calibrate FreqOffset\n");
		result = 0;
		goto success;
	}
	if(result == 1)
	{
		//start next scan
		atbm_printk_always("start next scan\n");

		//mutex_lock(&hw_priv->conf_mutex);
		//wsm_stop_tx(hw_priv);
		//mutex_unlock(&hw_priv->conf_mutex);

		msleep(100);
		txevm_total = 0;
		atbm_test_rx_cnt = 0;
		wsm_start_tx_v2(hw_priv,vif);
	}
	else  if(result == 0)  //etf dcxo success
	{
success:
		if((ErrCode = etf_v2_compare_test_result()) != 0)
			goto Error;
		atbm_printk_always("etf test success \n");
		gRxs_s.result = atbm_freqoffset_save_efuse(hw_priv,gRxs_s,dcxo);

		gRxs_s.dcxo = dcxo;
		gRxs_s.valid = 1;
#ifdef CONFIG_ATBM_ETF_OLD
		up(&hw_priv->scan.lock);
#endif
		hw_priv->etf_test_v2 = 0;
		//del_timer_sync(&hw_priv->etf_expire_timer);
#ifdef CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
		Atbm_Test_Success = 1;
		wsm_send_result(hw_priv,vif);
#endif
		
	}else
	{
Error:
		gRxs_s.result = ErrCode;
		gRxs_s.dcxo = dcxo;
		gRxs_s.valid = 1;
		atbm_printk_always("etf test Fail \n");
#ifdef CONFIG_ATBM_ETF_OLD
		up(&hw_priv->scan.lock);
#endif
		hw_priv->etf_test_v2 = 0;
		//del_timer_sync(&hw_priv->etf_expire_timer);
#ifdef CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
		Atbm_Test_Success = -1;
		wsm_send_result(hw_priv,vif);
#endif

	}
	atbm_test_rx_cnt = 0;
	txevm_total = 0;
	//ETF_bStartTx = 0;
	return result;
}

void etf_v2_scan_rx(struct atbm_common *hw_priv,struct sk_buff *skb,u8 rssi )
{

	s32 Cfo = 0;
	s32  RSSI = 0;
	s32 tmp = 0;
	s16 txevm  = 0;
	struct ATBM_TEST_IE  *Atbm_Ie = NULL;
	u8 *data = (u8 *)skb->data + offsetof(struct atbm_ieee80211_mgmt, u.probe_resp.variable);
	int len = skb->len - offsetof(struct atbm_ieee80211_mgmt, u.probe_resp.variable);
	Atbm_Ie = (struct ATBM_TEST_IE  *)LMC_FM_GetATBMIe(data,len);
	
	if((Atbm_Ie)
#ifdef ATBM_PRODUCT_TEST_USE_FEATURE_ID
		&& (Atbm_Ie->featureid == etf_config.featureid)
#endif
		)
	{
		tmp				= Atbm_Ie->result[1];
		tmp				= (s32)N_BIT_TO_SIGNED_32BIT(tmp, 16);
		if(Atbm_Ie->resverd & BIT(0))
			Cfo = (s32)(((tmp*12207)/160));//6431 as golden
		else
			Cfo = (s32)(((tmp*12207)/10));	//6421 as golden 
		txevm				= (s16)N_BIT_TO_SIGNED_32BIT(Atbm_Ie->result[2], 16);
		RSSI			= (s16)N_BIT_TO_SIGNED_32BIT(Atbm_Ie->result[3], 10);
		
		if( RSSI < etf_config.rssifilter)
		{
			atbm_printk_always("[%d]: Cfo:%d,TxRSSI:%d, rx dump packet,throw......\n",
			atbm_test_rx_cnt,	
			Cfo,
			RSSI
			);
			return;
		}

		if(txevm < etf_config.txevm)
		{
			if(atbm_test_rx_cnt == 0)
			{		
				gRxs_s.Cfo = Cfo;
				//gRxs_s.evm = evm;
				gRxs_s.TxRSSI = RSSI;
			}else
			{

				gRxs_s.Cfo = (gRxs_s.Cfo*3 + Cfo )/4;
				//gRxs_s.evm = evm;
				gRxs_s.TxRSSI = RSSI;
				//gRxs_s.TxRSSI = (gRxs_s.TxRSSI*3*10 + RSSI*10 +5)/40;

			}

			atbm_printk_always("[%d]: Cfo1:%d, Cfo:%d,TxRSSI:%d,txevm:%d\n",
			atbm_test_rx_cnt,
			tmp,
			Cfo,
			RSSI,txevm
			);

			//printk("etf_v2_scan_rx %d,cnt %d,[0x%x,0x%x,0x%x,0x%x,0x%x]\n",Atbm_Ie->test_type,atbm_test_rx_cnt,
			//	Atbm_Ie->result[0],Atbm_Ie->result[1],Atbm_Ie->result[2],Atbm_Ie->result[3],Atbm_Ie->result[3]);
			txevm_total += txevm;
			atbm_test_rx_cnt++;
		}
		
	}

}

/*
start return  1
stop return 0
*/
int ETF_Test_is_Start(void){
	if(ETF_bStartTx || ETF_bStartRx)
		return 1;
	return 0;
}

void ETF_Test_Init(void){
	ETF_bStartTx = 0;
	ETF_bStartRx = 0;
}

void etf_param_init(struct atbm_common *hw_priv)
{
	atbm_test_rx_cnt = 0;
	txevm_total = 0;

	ucWriteEfuseFlag = 0;

	CodeStart = DCXO_CODE_MINI;
	CodeEnd = DCXO_CODE_MAX;

	memset(&etf_config, 0, sizeof(struct etf_test_config));
	memset(&gRxs_s, 0, sizeof(struct rxstatus_signed));

	chipversion = GetChipVersion(hw_priv);
	atbm_printk_wext("chipversion:0x%x\n", chipversion);
}

