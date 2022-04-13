package rule

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"github.com/jweny/pocassist/pkg/db"
	log "github.com/jweny/pocassist/pkg/logging"
	"github.com/jweny/pocassist/pkg/util"
	"net/http"
	"net/url"
)

type ScanItem struct {
	OriginalReq *http.Request // 原始请求
	Plugin      *Plugin       // 检测插件
	Task        *db.Task      // 所属任务
}

func (item *ScanItem) Verify() error {
	errMsg := ""
	if item.Task == nil {
		errMsg = "task create fail"
		log.Error("[rule/parallel.go:Verify error]", errMsg)
		return errors.New(errMsg)
	}
	if item.OriginalReq == nil{
		errMsg = "not original request"
		log.Error("[rule/parallel.go:Verify error]", errMsg)
		return errors.New(errMsg)
	}
	if item.Plugin == nil {
		errMsg = "not plugin"
		log.Error("[rule/parallel.go:Verify error]", errMsg)
		return errors.New(errMsg)
	}
	return nil
}


func WriteTaskResult(scanItem *ScanItem, result *util.ScanResult) {
	// 过滤数据库已经存在的漏洞, server型截取第三个/之前，directory型截断最后一个/后的
	origUrl := scanItem.OriginalReq.URL
	targetUrl := result.Target
	if scanItem.Plugin.Affects == "server" {
		targetUrl = origUrl.Scheme + "://" + origUrl.Host
	} else if scanItem.Plugin.Affects == "directory" {
		targetUrl = origUrl.Scheme + "://" + origUrl.Host
		if origUrl.Path != "" {
			targetUrl += origUrl.Path[0:strings.LastIndex(origUrl.Path, "/")]
		}
	}
	pluginId := scanItem.Plugin.VulId
	results := db.GetSingleResult(targetUrl, pluginId)
	if len(results) > 0 {
		return
	}

	detail, _:= json.Marshal(result)
	res := db.Result{
		Detail:   detail,
		PluginId:  scanItem.Plugin.VulId,
		PluginName:	scanItem.Plugin.JsonPoc.Name,
		Vul:	result.Vulnerable,
		TaskId: scanItem.Task.Id,
	}
	db.AddResult(res)
	return
}

// 执行单个poc
func RunPoc(inter interface{}, debug bool) (result *util.ScanResult, err error) {
	scanItem := inter.(*ScanItem)
	err = scanItem.Verify()
	if err != nil {
		log.Error("[rule/poc.go:RunPoc scan item verify error] ", err)
		return nil, err
	}
	log.Info("[rule/poc.go:RunPoc current plugin]", scanItem.Plugin.JsonPoc.Name)

	var requestController RequestController
	var celController CelController

	err = requestController.Init(scanItem.OriginalReq)
	if err != nil {
		log.Error("[rule/poc.go:RunPoc request controller init error] ", err)
		return nil, err
	}

	handles := getHandles(scanItem.Plugin.Affects)

	err = celController.Init(scanItem.Plugin.JsonPoc)
	if err != nil {
		log.Error("[rule/poc.go:RunPoc cel controller init error] ", err)
		return nil, err
	}

	err = celController.InitSet(scanItem.Plugin.JsonPoc, requestController.New)
	if err != nil {
		util.RequestPut(requestController.New)
		log.Error("[rule/poc.go:RunPoc cel controller init set error] ", err)
		return nil, err
	}
	switch scanItem.Plugin.Affects {
	// 影响为参数类型
	case AffectAppendParameter, AffectReplaceParameter:
		{
			err := requestController.InitOriginalQueryParams()
			if err != nil {
				log.Error("[rule/poc.go:RunPoc init original request params error] ", err)
				return nil, err
			}
			controller := InitPocController(&requestController, scanItem.Plugin, &celController, handles)
			controller.Debug = debug
			paramPayloadList := scanItem.Plugin.JsonPoc.Params

			originalParamFields, err := url.ParseQuery(requestController.OriginalQueryParams)
			if err != nil {
				log.Error("[rule/poc.go:RunPoc params query parse error] ", err)
				return nil, err
			}

			for field := range originalParamFields {
				for _, payload := range paramPayloadList {
					log.Info("[rule/poc.go:RunPoc param payload]", payload)
					// 转换payload变量
					varMap := controller.CEL.ParamMap
					for setKey, setValue := range varMap {
						// 过滤掉 map
						_, isMap := setValue.(map[string]string)
						if isMap {
							continue
						}
						value := fmt.Sprintf("%v", setValue)
						// 替换payload中的 自定义字段
						payload = strings.ReplaceAll(strings.TrimSpace(payload), "{{"+setKey+"}}", value)
					}

					err = requestController.FixQueryParams(field, payload, controller.Plugin.Affects)
					if err != nil {
						log.Error("[rule/poc.go:RunPoc fix request params error] ", err)
						continue
					}
					controller.Next()
					if controller.IsAborted() {
						// 存在漏洞
						result = util.VulnerableHttpResult(controller.GetOriginalReq().URL.String(), payload, controller.Request.Raw)
						WriteTaskResult(scanItem, result)
						PutController(controller)
						return result, nil
					}
					controller.Index = 0
				}
			}
			// 没漏洞
			result = &util.InVulnerableResult
			PutController(controller)
			return result, nil
		}
	case AffectDirectory, AffectServer, AffectURL, AffectContent:
		{
			controller := InitPocController(&requestController, scanItem.Plugin, &celController, handles)
			controller.Debug = debug
			controller.Next()
			if controller.IsAborted() {
				// 存在漏洞
				result = util.VulnerableHttpResult(controller.GetOriginalReq().URL.String(), "", controller.Request.Raw)
				WriteTaskResult(scanItem, result)
				PutController(controller)
				return result, nil
			} else if debug{
				// debug 没漏洞
				result = util.DebugVulnerableHttpResult(controller.GetOriginalReq().URL.String(), "", controller.Request.Raw)
				PutController(controller)
				return result, nil
			}else {
				// 没漏洞
				result = &util.InVulnerableResult
				PutController(controller)
				return result, nil
			}
		}
	case AffectScript:
		{
			controller := InitPocController(&requestController, scanItem.Plugin, &celController, handles)
			controller.Debug = debug
			controller.Next()
			if controller.IsAborted() && controller.ScriptResult != nil && controller.ScriptResult.Vulnerable {
				// 存在漏洞 保存结果
				result = &util.ScanResult{
					Vulnerable: controller.ScriptResult.Vulnerable,
					Target:     controller.ScriptResult.Target,
					Output:     controller.ScriptResult.Output,
					ReqMsg:     controller.ScriptResult.ReqMsg,
					RespMsg:    controller.ScriptResult.RespMsg,
				}
				WriteTaskResult(scanItem, controller.ScriptResult)
				PutController(controller)
				return result, nil
			} else if debug {
				// debug 没漏洞
				result = util.DebugVulnerableHttpResult(controller.GetOriginalReq().URL.String(), "", controller.Request.Raw)
				PutController(controller)
				return result, nil
			} else {
				// 没漏洞
				PutController(controller)
				return &util.InVulnerableResult, nil
			}
		}
	}
	// 默认返回没有漏洞
	return &util.InVulnerableResult, nil
}