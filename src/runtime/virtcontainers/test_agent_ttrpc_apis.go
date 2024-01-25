package virtcontainers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unsafe"
	"github.com/sirupsen/logrus"
)

var (
	// Key:  API name to test
	// Value:struct implementing the CallTtrpcReq interface
	// This allows to implement only the Unmarshaler interface (and not the Marshaler) since we
	// can use the 'Api' field in the JSON encoded object.
	apiMap = map[string]reflect.Type{
		"CopyFileRequest" : reflect.TypeOf(CopyFileReq{}),
		"SetPolicyRequest": reflect.TypeOf(SetPolicyReq{}),
	}

	// to enable more verbose logging
	logger = logrus.WithFields(logrus.Fields{"ttrpc-test": "logs"})
)

func getAgentInterface(sandbox VCSandbox) any {
	var agentVal = reflect.Indirect(reflect.ValueOf(sandbox)).FieldByName("agent")
	var unsafeVal = reflect.NewAt(agentVal.Type(), unsafe.Pointer(agentVal.UnsafeAddr())).Elem()
	return unsafeVal.Interface()
}

// Defining an Interface for testing the Agent Ttrpc API request by forwarding to a virtcontainers endpoint.
type CallTtrpcReq interface {
	CallApi(context.Context, VCSandbox) error
}

// Base Struct for each Request
type TtrpcTestReq struct {
	Api       string
	SandboxID string
	Params    CallTtrpcReq
}

// Implement Unmarshaller for TtrpcTestReq
func (ttreq *TtrpcTestReq) UnmarshalJSON(b []byte) error {
	var data struct {
		Api string
		SandboxID string
		Params json.RawMessage
	}

	if err := json.Unmarshal(b, &data); err != nil {
		logger.Error("DEBUG: ttrpc-test: failed to unmarshal JSON to custom object.")
		return err
	}

	if apiHandlerType, found := apiMap[data.Api]; found {
		handlerType := reflect.New(apiHandlerType)

		if err := json.Unmarshal(data.Params, handlerType.Interface()); err != nil {
			logger.Error("DEBUG: ttrpc-test: failed to unmarshal JSON for Params field.")
			return err
		}

		ttreq.Params = handlerType.Elem().Interface().(CallTtrpcReq)
		return nil
	}

	logger.WithFields(logrus.Fields{"api": fmt.Sprintf("%s", data.Api),}).Error("DEBUG: ttrpc-test: Agent Api is not valid")

	return errors.New("ttrpc-test: Failed to unmarshal encoded JSON")
}

// Agent API: CopyFileRequest
type CopyFileReq struct {
	Src  string
	Dest string
}

func (cp CopyFileReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: ttrpc-test: testing copyFile Api")
	return getAgentInterface(sandbox).(*kataAgent).copyFile(ctx, cp.Src, cp.Dest)
}

// Agent API: SetPolicy
type SetPolicyReq struct {
	Buf []byte
}

func (sp SetPolicyReq) CallApi(ctx context.Context, sandbox VCSandbox) error {
	logrus.Error("DEBUG: ttrpc-test: testing setPolicy Api")
	return getAgentInterface(sandbox).(*kataAgent).setPolicy(ctx, string(sp.Buf))
}

func TestApi(ctx context.Context, input []byte, sandbox VCSandbox) error {
	// Unmarshal the request. We need to implement Unmarshaller since the request struct has one field as interface
	request := TtrpcTestReq{}

	// TtrpcTestReq struct implements Unmarshaller interface.
	// This is needed since the struct has a field of interface type.
	if err := json.Unmarshal(input, &request); err != nil {
		return err
	}

	// Call the API
	if err := request.Params.CallApi(ctx, sandbox); err != nil {
		return err
	}

	return nil
}
