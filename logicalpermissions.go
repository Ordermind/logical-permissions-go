package logicalpermissions

import (
  "fmt"
  "encoding/json"
  "strconv"
)

type LogicalPermissions struct {
  types map[string]func(string, map[string]interface{}) (bool, error)
  bypass_callback func(map[string]interface{}) (bool, error)
}

func (this *LogicalPermissions) AddType(name string, callback func(string, map[string]interface{}) (bool, error)) error {
  if name == "" {
    return &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  types := this.GetTypes()
  types[name] = callback
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) RemoveType(name string) error {
  if name == "" {
    return &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}  
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}}
  }
  types := this.GetTypes()
  delete(types, name)
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) TypeExists(name string) (bool, error) {
  if name == "" {
    return false, &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  types := this.GetTypes()
  if _, ok := types[name]; ok {
    return true, nil
  }
  return false, nil
}

func (this *LogicalPermissions) GetTypeCallback(name string) (func(string, map[string]interface{}) (bool, error), error) {
  if name == "" {
    return nil, &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return nil, &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}}
  }
  types := this.GetTypes()
  return types[name], nil
}

func (this *LogicalPermissions) GetTypes() map[string]func(string, map[string]interface{}) (bool, error) {
  if this.types == nil {
    this.types = make(map[string]func(string, map[string]interface{}) (bool, error))
  }
  types := make(map[string]func(string, map[string]interface{}) (bool, error))
  for name, callback := range this.types {
    types[name] = callback
  }
  return types
}

func (this *LogicalPermissions) SetTypes(types map[string]func(string, map[string]interface{}) (bool, error)) error {
  for name, _ := range types {
    if name == "" {
      return &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
    }
  }

  this.types = make(map[string]func(string, map[string]interface{}) (bool, error))
  for name, callback := range types {
    this.types[name] = callback
  }
  return nil
}

func (this *LogicalPermissions) GetBypassCallback() func(map[string]interface{}) (bool, error) {
  return this.bypass_callback
}

func (this *LogicalPermissions) SetBypassCallback(callback func(map[string]interface{}) (bool, error)) {
  this.bypass_callback = callback
}

func (this *LogicalPermissions) CheckAccess(json_permissions string, context map[string]interface{}) (bool, error) {
  allow_bypass := false
  var permissions map[string]interface{}
  err := json.Unmarshal([]byte(json_permissions), &permissions)
  if err != nil {
    return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("Error parsing json_permissions: %s", err.Error())}}
  }
  if val, ok := permissions["no_bypass"]; ok {
    if boolval, ok := val.(bool); ok {
      allow_bypass = !boolval
    } else if mapval, ok := val.(map[string]interface{}); ok {
      result, err_custom := this.processOR(mapval, "", context)
      allow_bypass = !result
      if err_custom != nil {
        err_custom.setMessage(fmt.Sprintf("Error checking no_bypass permissions: %s", err_custom.Error()))
        return false, err_custom
      }
    } else {
      return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("The no_bypass value must be a boolean or a map. Current value: %v", val)}}
    }
    delete(permissions, "no_bypass")
    
    if allow_bypass {
      access, err_custom := this.checkBypassAccess(context)
      if err_custom != nil {
        err_custom.setMessage(fmt.Sprintf("Error checking bypass access: %s", err_custom.Error()))
        return false, err_custom
      }
      return access, nil
    }
    if len(permissions) > 0 {
      access, err_custom := this.processOR(permissions, "", context)
      if err_custom != nil {
        err_custom.setMessage(fmt.Sprintf("Error checking access: %s", err_custom.Error()))
        return false, err_custom
      }
      return access, nil
    }
  }
  return false, nil
}

func (this *LogicalPermissions) checkBypassAccess(context map[string]interface{}) (bool, CustomErrorInterface) {
  bypass_callback := this.GetBypassCallback()
  bypass_access, err_custom := bypass_callback(context)
  if err_custom != nil {
    return false, &CustomError{err_custom.Error()} 
  }

  return bypass_access, nil
}

func (this *LogicalPermissions) dispatch(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if str_permissions, ok := permissions.(string); ok {
    access, err_custom := this.externalAccessCheck(str_permissions, permtype, context)
    if err_custom != nil {
      return false, err_custom
    }
    return access, nil
  } 
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) > 0 {
      access, err_custom := this.processOR(slice_permissions, permtype, context) 
      if err_custom != nil {
        return false, err_custom
      }
      return access, nil
    }
    return false, nil
  }
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) == 1 {
      key := ""
      for k, _ := range map_permissions {
        key = k
        break
      }
      value := map_permissions[key]
      if key == "AND" {
        access, err_custom := this.processAND(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "NAND" {
        access, err_custom := this.processNAND(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "OR" {
        access, err_custom := this.processOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "NOR" {
        access, err_custom := this.processNOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "XOR" {
        access, err_custom := this.processXOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "NOT" {
        access, err_custom := this.processNOT(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if _, err := strconv.Atoi(key); err != nil {
        if permtype == "" {
          permtype = key 
        } else {
          return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("You cannot put a permission type as a descendant to another permission type. Existing type: %s. Evaluated permissions: %v", permtype, map_permissions)}}
        }
      }
      value_type := ""
      if _, ok := value.([]interface{}); ok {
        value_type = "slice"
      } else if _, ok := value.(map[string]interface{}); ok {
        value_type = "map" 
      }
      if value_type == "slice" || value_type == "map" {
        access, err_custom := this.processOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }

      access, err_custom := this.dispatch(value, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      return access, nil

    }
    if len(map_permissions) > 1 {
      access, err_custom := this.processOR(map_permissions, permtype, context) 
      if err_custom != nil {
        return false, err_custom
      }
      return access, nil
    }
    return false, nil
  } 
    
  return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("A permission value must either be a string, a slice or an map. Evaluated permissions: %v", permissions)}}
}

func (this *LogicalPermissions) processAND(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  access := false
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of an AND gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }
    
    access = true
    for _, permission := range slice_permissions {
      result, err := this.dispatch(permission, permtype, context)
      if err != nil {
        return false, err
      }
      access = access && result
      if !access {
        break 
      }
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of an AND gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }
    
    access = true
    for k, v := range map_permissions {
      subpermissions := map[string]interface{}{k: v}
      result, err := this.dispatch(subpermissions, permtype, context)
      if err != nil {
        return false, err
      }
      access = access && result
      if !access {
        break 
      }
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of an AND gate must be a slice or map. Current value: %v", permissions)}}
  }
  return access, nil
}

func (this *LogicalPermissions) processNAND(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of a NAND gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of a NAND gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of a NAND gate must be a slice or map. Current value: %v", permissions)}}
  }
  
  result, err := this.processAND(permissions, permtype, context)
  if err != nil {
    return false, err
  }
  access := !result
  return access, nil
}

func (this *LogicalPermissions) processOR(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  access := false
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of an OR gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }

    for _, permission := range slice_permissions {
      result, err := this.dispatch(permission, permtype, context)
      if err != nil {
        return false, err
      }
      access = access || result
      if access {
        break 
      }
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of an OR gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }

    for k, v := range map_permissions {
      subpermissions := map[string]interface{}{k: v}
      result, err := this.dispatch(subpermissions, permtype, context)
      if err != nil {
        return false, err
      }
      access = access || result
      if access {
        break 
      }
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of an OR gate must be a slice or map. Current value: %v", permissions)}}
  }
  return access, nil
}

func (this *LogicalPermissions) processNOR(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of a NOR gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of a NOR gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of a NOR gate must be a slice or map. Current value: %v", permissions)}}
  }
  
  result, err := this.processOR(permissions, permtype, context)
  if err != nil {
    return false, err
  }
  access := !result
  return access, nil
}

func (this *LogicalPermissions) processXOR(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  access := false
  count_true := 0
  count_false := 0
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 2 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of an XOR gate must contain a minimum of two elements. Current value: %v", slice_permissions)}}
    }
    
    for _, permission := range slice_permissions {
      result, err := this.dispatch(permission, permtype, context)
      if err != nil {
        return false, err
      }
      if result {
        count_true++ 
      } else {
        count_false++ 
      }
      if count_true > 0 && count_false > 0 {
        access = true
        break
      }
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 2 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of an XOR gate must contain a minimum of two elements. Current value: %v", map_permissions)}}
    }
    
    for k, v := range map_permissions {
      subpermissions := map[string]interface{}{k: v}
      result, err := this.dispatch(subpermissions, permtype, context)
      if err != nil {
        return false, err
      }
      if result {
        count_true++ 
      } else {
        count_false++ 
      }
      if count_true > 0 && count_false > 0 {
        access = true
        break
      }
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of an XOR gate must be a slice or map. Current value: %v", permissions)}}
  }
  return access, nil
}

func (this *LogicalPermissions) processNOT(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) != 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("A NOT permission must have exactly one child in the value map. Current value: %v", map_permissions)}}
    }
  } else if str_permissions, ok := permissions.(string); ok {
    if str_permissions == "" {
      return false, &InvalidValueForLogicGateError{CustomError{"A NOT permission cannot have an empty string as its value."}}
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of a NOT gate must be a map or string. Current value: %v", permissions)}}
  }
  
  result, err := this.dispatch(permissions, permtype, context)
  if err != nil {
    return false, err
  }
  access := !result
  return access, nil
}

func (this *LogicalPermissions) externalAccessCheck(permission string, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  exists, err := this.TypeExists(permtype)
  if err != nil {
    return false, &CustomError{err.Error()}
  }
  if !exists {
    return false, &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::addType() or LogicalPermissions::setTypes() to register permission types.", permtype)}}
  }
  
  callback, err := this.GetTypeCallback(permtype)
  if err != nil {
    return false, &CustomError{err.Error()} 
  }

  access, err := callback(permission, context)
  if err != nil {
    return false, &CustomError{err.Error()}
  }

  return access, nil
}