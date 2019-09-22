/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
ESP32 Cgi/template routines for the /wifi url.
*/

#include <libesphttpd/esp.h>
#include <libesphttpd/cgiwifi.h>

#if defined(ESP32)
#include <stdatomic.h>
#include <errno.h>

#include <freertos/FreeRTOS.h>
#include <freertos/timers.h>
#include <freertos/event_groups.h>

#include <esp_wifi_types.h>
#include <esp_wifi.h>
#include <esp_wps.h>
#include <esp_log.h>

#include <kutils.h>
#include <kref.h>
#include <wifi_manager.h>

static const char *TAG = "esp32_cgiwifi";
/* Enable this to disallow any changes in AP settings. */
//#define DEMO_MODE

#define SCAN_STALE_MS   30000

struct ap_data_iter{
    struct scan_data *data;
    uint16_t idx;
};

/* This CGI is called from the bit of AJAX-code in wifi.tpl. It will       *\
 * initiate a scan for access points and if available will return the      *
 * result of an earlier scan. The result is embedded in a bit of JSON      *
\* parsed by the javascript in wifi.tpl.                                   */
CgiStatus cgiWiFiScan(HttpdConnData *connData)
{
    TickType_t now;
    struct ap_data_iter *iter;
    struct scan_data *data;
    wifi_ap_record_t *record;
    wifi_mode_t mode;
    CgiStatus result;
    int len;
    char buff[1024];

    result = HTTPD_CGI_DONE;
    iter = (struct ap_data_iter *) connData->cgiData;

    if(connData->isConnectionClosed){
        goto on_exit;
    }

    if(esp_wifi_get_mode(&mode) != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        goto on_exit;
    }

    /* First call. Send header, fetch scan data and set up iterator. */
    if(iter == NULL){
        httpdStartResponse(connData, 200);
        httpdHeader(connData, "Content-Type", "text/json");
        httpdEndHeaders(connData);

        data = esp_wmngr_get_scan();

        /* Discard stale scan data. */
        if(data != NULL){
            now = xTaskGetTickCount();
            if(time_after(now, data->tstamp + pdMS_TO_TICKS(SCAN_STALE_MS))){
                esp_wmngr_put_scan(data);
                data = NULL;
            }
        }

        if(data != NULL){
            /* Scan data is valid. Set up iterator struct so entries can *\
            \* be sent out on subsequent calls.                          */ 
            iter = calloc(1, sizeof(*iter));
            if(iter != NULL){
                iter->data = data;
                iter->idx = 0;
                connData->cgiData = (void *) iter;
            } else {
                ESP_LOGE(TAG, "[%s] Iterator allocation failed.", __FUNCTION__);
                esp_wmngr_put_scan(data);
            }
        } else {
            /* There was no scan data available or it was stale. Start scan. */
            esp_wmngr_start_scan();
        }
    }

    if(iter == NULL){
        /* There is either no scan data available or iterator allocation    *\
        \* failed. Tell the user we are still trying...                     */
        len=sprintf(buff, "{\n \"result\": { \n\"inProgress\": \"1\"\n }\n}\n");
        httpdSend(connData, buff, len);
    } else {
        /* We have data to send. Send JSON opening before sending first AP  *\
        \* data from the list.                                              */
        if(iter->idx == 0){
            len = sprintf(buff, "{\n \"result\": { \n"
                                "\"inProgress\": \"0\", \n"
                                "\"APs\": [\n");
            httpdSend(connData, buff, len);
        }

        /* Skip sending stale AP data if we are in AP mode. */
        if(mode == WIFI_MODE_AP){
            iter->idx = iter->data->num_records;
        }

        /* If list is not empty, send current AP element data and advance   *\
        \* element pointer.                                                 */
        if(iter->idx < iter->data->num_records){
            record = &(iter->data->ap_records[iter->idx]);
            ++iter->idx;

            len = sprintf(buff, "{\"essid\": \"%s\", "
                                "\"bssid\": \"" MACSTR "\", "
                                "\"rssi\": \"%d\", "
                                "\"enc\": \"%d\", "
                                "\"channel\": \"%d\"}%s\n",
                                record->ssid,
                                MAC2STR(record->bssid),
                                record->rssi,
                                record->authmode == WIFI_AUTH_OPEN ? 0 :
                                record->authmode == WIFI_AUTH_WEP  ? 1 : 2,
                                record->primary,
                                iter->idx < iter->data->num_records ? "," : "");
            httpdSend(connData, buff, len);
        }

        /* Close JSON statement when all elements have been sent. */
        if(iter->idx >= iter->data->num_records){
            len = sprintf(buff, "]\n}\n}\n");
            httpdSend(connData, buff, len);
        } else {
            /* Still more data to send... */
            result = HTTPD_CGI_MORE;
        }
    }

on_exit:
    if(result == HTTPD_CGI_DONE && iter != NULL){
        esp_wmngr_put_scan(iter->data);
        free(iter);
        connData->cgiData = NULL;
    }

    return result;
}

/* Trigger a connection attempt to the AP with the given SSID and password. */
CgiStatus cgiWiFiConnect(HttpdConnData *connData)
{
    int len;
    const char *redirect;
    struct wifi_cfg cfg;
    wifi_sta_config_t *sta;
    esp_err_t result;

    if (connData->isConnectionClosed) {
        /* Connection aborted. Clean up. */
        return HTTPD_CGI_DONE;
    }

    redirect = "wifi.tpl";
    memset(&cfg, 0x0, sizeof(cfg));

    /* We are only changing SSID and password, so fetch the current *\
    \* configuration and update just these two entries.             */
    result = esp_wmngr_get_cfg(&cfg);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching WiFi config.", __FUNCTION__);
        goto on_exit;
    }

    sta = &(cfg.sta.sta);
    len = httpdFindArg(connData->post.buff, "essid",
                       (char *) &(sta->ssid), sizeof(sta->ssid));
    if(len <= 1){
        ESP_LOGE(TAG, "[%s] essid invalid or missing.", __FUNCTION__);
        goto on_exit;
    }

    len = httpdFindArg(connData->post.buff, "passwd",
                       (char *) &(sta->password), sizeof(sta->password));
    if(len <= 1){
        /* FIXME: What about unsecured APs? */
        ESP_LOGE(TAG, "[%s] Password parameter missing.", __FUNCTION__);
        goto on_exit;
    }

    /* And of course we want to actually connect to the AP. */
    cfg.sta_connect = true;

#ifndef DEMO_MODE
    ESP_LOGI(TAG, "Trying to connect to AP %s pw %s",
            sta->ssid, sta->password);

    result = esp_wmngr_set_cfg(&cfg);
    if(result == ESP_OK){
        redirect = "connecting.html";
    }
#else
    ESP_LOGI(TAG, "Demo mode, not actually connecting to AP %s pw %s",
            sta->ssid, sta->password);
#endif

on_exit:
    httpdRedirect(connData, redirect);
    return HTTPD_CGI_DONE;
}

/* CGI used to set the WiFi mode. */
CgiStatus cgiWiFiSetMode(HttpdConnData *connData)
{
    int len;
    wifi_mode_t mode;
    struct wifi_cfg cfg;
    char buff[16];
    esp_err_t result;

    if (connData->isConnectionClosed) {
        /* Connection aborted. Clean up. */
        return HTTPD_CGI_DONE;
    }

    len=httpdFindArg(connData->getArgs, "mode", buff, sizeof(buff));
    if (len!=0) {
        errno = 0;
        mode = strtoul(buff, NULL, 10);
        if(errno != 0 || mode <= WIFI_MODE_NULL || mode >= WIFI_MODE_MAX){
            ESP_LOGE(TAG, "[%s] Invalid WiFi mode: %d", __FUNCTION__, cfg.mode);
            goto on_exit;
        }

#ifndef DEMO_MODE
        memset(&cfg, 0x0, sizeof(cfg));

        result = esp_wmngr_get_cfg(&cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Error fetching current WiFi config.",
                     __FUNCTION__);
            goto on_exit;
        }

        /* Do not switch to STA mode without being connected to an AP. */
        if(mode == WIFI_MODE_STA && !esp_wmngr_is_connected()){
            ESP_LOGE(TAG, "[%s] No connection to AP, not switching to "
                          "client-only mode.", __FUNCTION__);
            goto on_exit;
        }

        cfg.mode = mode;

        ESP_LOGI(TAG, "[%s] Switching to WiFi mode %s",
                 __FUNCTION__,
                 mode == WIFI_MODE_AP    ? "SoftAP" :
                 mode == WIFI_MODE_APSTA ? "STA+AP" :
                 mode == WIFI_MODE_STA   ? "Client" : "Disabled");

        result = esp_wmngr_set_cfg(&cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Setting WiFi config failed", __FUNCTION__);
        }
#else
        ESP_LOGI(TAG, "[%s] Demo mode, not switching to WiFi mode %s",
                 __FUNCTION__,
                 mode == WIFI_MODE_AP    ? "SoftAP" :
                 mode == WIFI_MODE_APSTA ? "STA+AP" :
                 mode == WIFI_MODE_STA   ? "Client" : "Disabled");
#endif
    }

on_exit:
    /* changing mode takes some time, so redirect user to wait */
    httpdRedirect(connData, "working.html");
    return HTTPD_CGI_DONE;
}

/* CGI for triggering a WPS push button connection attempt. */
CgiStatus cgiWiFiStartWps(HttpdConnData *connData)
{
    esp_err_t result;

    result = ESP_OK;

    if (connData->isConnectionClosed) {
        /* Connection aborted. Clean up. */
        return HTTPD_CGI_DONE;
    }

#if defined(DEMO_MODE)
    ESP_LOGI(TAG, "[%s] Demo mode, not starting WPS.", __FUNCTION__);
#else
    ESP_LOGI(TAG, "[%s] Starting WPS.", __FUNCTION__);

    result = esp_wmngr_start_wps();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error starting WPS.", __FUNCTION__);
    }
#endif

    httpdRedirect(connData, "connecting.html");

    return HTTPD_CGI_DONE;
}

/* CGI for settings in AP mode. */
CgiStatus cgiWiFiAPSettings(HttpdConnData *connData)
{
    int len;
    char buff[64];

    esp_err_t result;

    if (connData->isConnectionClosed) {
        return HTTPD_CGI_DONE;
    }

    bool has_arg_chan = false;
    unsigned int chan;
    len = httpdFindArg(connData->post.buff, "chan", buff, sizeof(buff));
    if(len > 0){
        errno = 0;
        chan = strtoul(buff, NULL, 10);
        if(errno != 0 || chan < 1 || chan > 15){
            ESP_LOGW(TAG, "[%s] Not setting invalid channel %s",
                    __FUNCTION__, buff);
        } else {
            has_arg_chan = true;
        }
    }

    bool has_arg_ssid = false;
    char ssid[32];           /**< SSID of ESP32 soft-AP */
    len = httpdFindArg(connData->post.buff, "ssid", buff, sizeof(buff));
    if(len > 0){
        int n;
        n = sscanf(buff, "%s", (char*)&ssid); // find a string without spaces
        if (n == 1) {
            has_arg_ssid = true;
        } else {
            ESP_LOGW(TAG, "[%s] Not setting invalid ssid %s",
                    __FUNCTION__, buff);
        }
    }

    bool has_arg_pass = false;
    char pass[64];       /**< Password of ESP32 soft-AP */
    len = httpdFindArg(connData->post.buff, "pass", buff, sizeof(buff));
    if(len > 0){
        int n;
        n = sscanf(buff, "%s", (char*)&pass); // find a string without spaces
        if (n == 1) {
            has_arg_pass = true;
        } else {
            ESP_LOGW(TAG, "[%s] Not setting invalid pass %s",
                    __FUNCTION__, buff);
        }
    }

    if (has_arg_chan || has_arg_ssid || has_arg_pass) {
#ifndef DEMO_MODE
        struct wifi_cfg cfg;
        result = esp_wmngr_get_cfg(&cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Fetching WiFi config failed", __FUNCTION__);
            goto on_exit;
        }

        if (has_arg_chan) {
            ESP_LOGI(TAG, "[%s] Setting ch=%d", __FUNCTION__, chan);
            cfg.ap.ap.channel = (uint8) chan;
        }

        if (has_arg_ssid) {
            ESP_LOGI(TAG, "[%s] Setting ssid=%s", __FUNCTION__, ssid);
            strlcpy((char*)cfg.ap.ap.ssid, ssid, sizeof(cfg.ap.ap.ssid));
            cfg.ap.ap.ssid_len = 0;  // if ssid_len==0, check the SSID until there is a termination character; otherwise, set the SSID length according to softap_config.ssid_len.
            ESP_LOGI(TAG, "[%s] Set ssid=%s", __FUNCTION__, cfg.ap.ap.ssid);
        }

        if (has_arg_pass) {
            ESP_LOGI(TAG, "[%s] Setting pass=%s", __FUNCTION__, pass);
            strlcpy((char*)cfg.ap.ap.password, pass, sizeof(cfg.ap.ap.password));
        }

        result = esp_wmngr_set_cfg(&cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Setting WiFi config failed", __FUNCTION__);
        }
#else
        ESP_LOGI(TAG, "[%s] Demo mode, not setting ch=%d", __FUNCTION__, chan);
#endif
    }

on_exit:
    httpdRedirect(connData, "working.html");
    return HTTPD_CGI_DONE;
}

/* CGI returning the current state of the WiFi connection. */
CgiStatus cgiWiFiConnStatus(HttpdConnData *connData)
{
    char buff[128];
    enum wmngr_state state;
    tcpip_adapter_ip_info_t info;
    esp_err_t result;

    if (connData->isConnectionClosed) {
        return HTTPD_CGI_DONE;
    }

    snprintf(buff, sizeof(buff) - 1, "{\n \"status\": \"fail\"\n }\n");

    state = esp_wmngr_get_state();

    switch(state){
    case wmngr_state_idle:
        snprintf(buff, sizeof(buff) - 1, "{\n \"status\": \"idle\"\n }\n");
        break;
    case wmngr_state_update:
    case wmngr_state_connecting:
    case wmngr_state_disconnecting:
    case wmngr_state_wps_start:
    case wmngr_state_wps_active:
    case wmngr_state_fallback:
        snprintf(buff, sizeof(buff) - 1, "{\n \"status\": \"working\"\n }\n");
        break;
    case wmngr_state_connected:
        result = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &info);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Error fetching IP config.", __FUNCTION__);
            goto on_error;
        }
        snprintf(buff, sizeof(buff) - 1,
                "{\n \"status\": \"success\",\n \"ip\": \"%s\" }\n",
                ip4addr_ntoa(&(info.ip)));
        break;
    case wmngr_state_failed:
    default:
        break;
    }

    httpdStartResponse(connData, 200);
    httpdHeader(connData, "Content-Type", "text/json");
    httpdEndHeaders(connData);
    httpdSend(connData, buff, -1);
    return HTTPD_CGI_DONE;

on_error:
    ESP_LOGE(TAG, "[%s] Failed.", __FUNCTION__);
    httpdStartResponse(connData, 500);
    httpdEndHeaders(connData);

    return HTTPD_CGI_DONE;
}

/* Template code for the WiFi page. */
CgiStatus tplWlan(HttpdConnData *connData, char *token, void **arg)
{
    char buff[600];
    wifi_ap_record_t stcfg;
    wifi_mode_t mode;
    esp_err_t result;

    if(token == NULL){
        goto on_exit;
    }

    memset(buff, 0x0, sizeof(buff));

    if(!strcmp(token, "WiFiMode")){
        result = esp_wifi_get_mode(&mode);
        if(result != ESP_OK){
            goto on_exit;
        }

        switch(mode){
        case WIFI_MODE_STA:
            strlcpy(buff, "STA (Client Only)", sizeof(buff));
            break;
        case WIFI_MODE_AP:
            strlcpy(buff, "AP (Access Point Only)", sizeof(buff));
            break;
        case WIFI_MODE_APSTA:
            strlcpy(buff, "STA+AP", sizeof(buff));
            break;
        default:
            strlcpy(buff, "Disabled", sizeof(buff));
            break;
        }
    } else if(!strcmp(token, "currSsid")){
        wifi_config_t cfg;
        //if(sta_connected()){
            result = esp_wifi_get_config(WIFI_IF_STA, &cfg);
            if(result != ESP_OK){
                ESP_LOGE(TAG, "[%s] Error fetching STA config.", __FUNCTION__);
                goto on_exit;
            }
            strlcpy(buff, (char*)cfg.sta.ssid, sizeof(buff));
        //}
    } else if(!strcmp(token, "WiFiPasswd")){
        wifi_config_t cfg;
        //if(esp_wmngr_is_connected()){
            result = esp_wifi_get_config(WIFI_IF_STA, &cfg);
            if(result != ESP_OK){
                ESP_LOGE(TAG, "[%s] Error fetching STA config.", __FUNCTION__);
                goto on_exit;
            }
            strlcpy(buff, (char*)cfg.sta.password, sizeof(buff));
        //}
    } else if(!strcmp(token, "ApSsid")){
        wifi_config_t cfg;
        result = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
            goto on_exit;
        }
        strlcpy(buff, (char*)cfg.ap.ssid, sizeof(buff));

    } else if(!strcmp(token, "ApPass")){
        wifi_config_t cfg;
        result = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
            goto on_exit;
        }
        strlcpy(buff, (char*)cfg.ap.password, sizeof(buff));

    } else if(!strcmp(token, "ApChan")){
        wifi_config_t cfg;
        result = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
            goto on_exit;
        }
        snprintf(buff, sizeof(buff), "%d", cfg.ap.channel);

    } else if(!strcmp(token, "ModeWarn")){
        result = esp_wifi_get_mode(&mode);
        if(result != ESP_OK){
            goto on_exit;
        }

        switch(mode){
        case WIFI_MODE_AP:
            /* In AP mode we do not offer switching to STA-only mode.   *\
             * This should minimise the risk of the system connecting   *
             * to an AP the user can not access and thereby losing      *
             * control of the device. By forcing them to go through the *
             * AP+STA mode, the user will always be able to rescue the  *
             * situation via the AP interface.                          *
             * Maybe we should also implement an aknowledge mechanism,  *
             * where the user will have to load a certain URL within    *
             * x minutes after switching to STA mode, otherwise the     *
            \* device will fall back to the previous configuration.     */
            snprintf(buff, sizeof(buff) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\""
                    ">Go to <b>AP+STA</b> mode</button> "
                    "(Both AP and Client)</p>",
                    WIFI_MODE_APSTA);
            break;
        case WIFI_MODE_APSTA:
            snprintf(buff, sizeof(buff) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\""
                    ">Go to standalone <b>AP</b> mode</button> "
                    "(Access Point Only)</p>",
                    WIFI_MODE_AP);

            /* Only offer switching to STA mode if we have a connection. */
            if(esp_wmngr_is_connected()){
                snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff) - 1,
                        "<p><button onclick=\"location.href='setmode.cgi?"
                        "mode=%d'\">Go to standalone <b>STA</b> mode</button> "
                        "(Client Only)</p>",
                        WIFI_MODE_STA);
            }
            break;
        case WIFI_MODE_STA:
        default:
            snprintf(buff, sizeof(buff) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\""
                    ">Go to standalone <b>AP</b> mode</button> "
                    "(Access Point Only)</p>"
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\""
                    ">Go to <b>AP+STA</b> mode</button> "
                    "(Both AP and Client)</p>",
                    WIFI_MODE_AP, WIFI_MODE_APSTA);
            break;
        }

        /* Always offer WPS. */
        snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff) - 1,
                "<p><button onclick=\"location.href='startwps.cgi'\">Connect "
                "to AP with <b>WPS</b></button> "
                "This will switch to AP+STA mode. You can switch to STA only "
                "mode after the client has connected.</p>");

        /* Disable WiFi.  (only available if Eth connected?) */
        if(1){//eth_connected()){
            snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\""
                    ">Disable WiFi</button> "
                    "This option may leave you unable to connect!"
                    " (unless via Ethernet.) </p>", WIFI_MODE_NULL);
        }

    } else if(!strcmp(token, "StaWarn")){
        result = esp_wifi_get_mode(&mode);
        if(result != ESP_OK){
            goto on_exit;
        }

        switch(mode){
        case WIFI_MODE_STA:
        case WIFI_MODE_APSTA:
            result = esp_wifi_sta_get_ap_info(&stcfg);
            if(result != ESP_OK){
                snprintf(buff, sizeof(buff) - 1, "STA is <b>not connected</b>.");
            } else {
                snprintf(buff, sizeof(buff) - 1,
                        "STA is connected to: <b>%s</b>",
                        (char*)stcfg.ssid);
            }
            break;
        case WIFI_MODE_AP:
        default:
            snprintf(buff, sizeof(buff) - 1,
                    "Warning: STA Disabled! <b>Can't scan in this mode.</b>");
            break;
        }
    }else if(!strcmp(token, "ApWarn")){
        result = esp_wifi_get_mode(&mode);
        if(result != ESP_OK){
            goto on_exit;
        }

        switch(mode){
        case WIFI_MODE_AP:
        case WIFI_MODE_APSTA:
            break;
        case WIFI_MODE_STA:
        default:
            snprintf(buff, sizeof(buff) - 1,
                    "Warning: AP Disabled!  "
                    "Save AP Settings will have no effect.");
            break;
        }
    }

    httpdSend(connData, buff, -1);

on_exit:
    return HTTPD_CGI_DONE;
}

#endif // ESP32
