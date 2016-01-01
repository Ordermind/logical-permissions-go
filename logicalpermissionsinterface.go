package logicalpermissions

type LogicalPermissionsInterface interface {
  AddType(name string, callback func(string, map[string]interface{}) bool) error
  RemoveType(name string) error
  TypeExists(name string) (bool, error)
  GetTypeCallback(name string) func(string, map[string]interface{}) bool
  GetTypes() map[string]func(string, map[string]interface{}) bool
  SetTypes(types map[string]func(string, map[string]interface{}) bool)
  GetBypassCallback() func(map[string]interface{}) bool
  SetBypassCallback(callback func(map[string]interface{}) bool)
  CheckAccess(permissions map[string]interface{}, context map[string]interface{}) bool
} 
