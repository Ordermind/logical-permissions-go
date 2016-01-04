package logicalpermissions

type LogicalPermissionsInterface interface {
  AddType(name string, callback func(string, map[string]interface{}) (bool, error)) error
  RemoveType(name string) error
  TypeExists(name string) (bool, error)
  GetTypeCallback(name string) (func(string, map[string]interface{}) (bool, error), error)
  GetTypes() map[string]func(string, map[string]interface{}) (bool, error)
  SetTypes(types map[string]func(string, map[string]interface{}) (bool, error)) error
  GetBypassCallback() func(map[string]interface{}) (bool, error)
  SetBypassCallback(callback func(map[string]interface{}) (bool, error))
  CheckAccess(json_permissions string, context map[string]interface{}) (bool, error)
} 
