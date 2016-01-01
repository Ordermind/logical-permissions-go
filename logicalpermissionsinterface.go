package logicalpermissions

type LogicalPermissionsInterface interface {
  AddType(name string, callback func(string, map[string]interface{}) bool)
  RemoveType(name string)
  TypeExists(name string) bool
  GetTypeCallback(name string) func(string, map[string]interface{}) bool
  GetTypes() map[string]interface{}
  SetTypes(types map[string]interface{})
  GetBypassCallback() func(map[string]interface{}) bool
  SetBypassCallback(callback func(map[string]interface{}) bool)
  CheckAccess(permissions map[string]interface{}, context map[string]interface{}) bool
} 
