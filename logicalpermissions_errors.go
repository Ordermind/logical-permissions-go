package logicalpermissions

type InvalidArgumentValueError struct {
    msg string
}

func (this *InvalidArgumentValueError) Error() string { return this.msg }

type InvalidValueForLogicGateError struct {
    msg string
}

func (this *InvalidValueForLogicGateError) Error() string { return this.msg }

type PermissionTypeNotRegisteredError struct {
    msg string
}

func (this *PermissionTypeNotRegisteredError) Error() string { return this.msg }

type InvalidCallbackReturnTypeError struct {
    msg string
}

func (this *InvalidCallbackReturnTypeError) Error() string { return this.msg }