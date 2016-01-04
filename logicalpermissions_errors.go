package logicalpermissions

type CustomErrorInterface interface {
  setMessage(msg string)
  Error() string
}

type CustomError struct {
  msg string
}

func (this *CustomError) setMessage(msg string) {
  this.msg = msg 
}

func (this *CustomError) Error() string { return this.msg }

type InvalidArgumentValueError struct {
  CustomError
}

type InvalidValueForLogicGateError struct {
  CustomError
}

type PermissionTypeNotRegisteredError struct {
  CustomError
}

type InvalidCallbackReturnTypeError struct {
  CustomError
}
