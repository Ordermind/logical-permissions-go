package logicalpermissions

import (
  "fmt"
  "encoding/json"
  "strconv"
)

type LogicalPermissions struct {
  types map[string]func(string, map[string]interface{}) bool
  bypass_callback func(map[string]interface{}) bool
}

func (this *LogicalPermissions) AddType(name string, callback func(string, map[string]interface{}) (bool, error)) error {
  if name == "" {
    return &InvalidArgumentValueError{"The name parameter cannot be empty."}  
  }
  types := this.GetTypes()
  types[name] = callback
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) RemoveType(name string) error {
  if name == "" {
    return &InvalidArgumentValueError{"The name parameter cannot be empty."}  
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return &PermissionTypeNotRegisteredError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}  
  }
  types := this.GetTypes()
  delete(types, name)
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) TypeExists(name string) (bool, error) {
  if name == "" {
    return false, &InvalidArgumentValueError{"The name parameter cannot be empty."}
  }
  types := this.GetTypes()
  if _, ok := types[name]; ok {
    return true, nil
  }
  return false, nil
}

func (this *LogicalPermissions) GetTypeCallback(name string) (func(string, map[string]interface{}) (bool, error), error) {
  if name == "" {
    return nil, &InvalidArgumentValueError{"The name parameter cannot be empty."}
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return nil, &PermissionTypeNotRegisteredError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}
  }
  types := this.GetTypes()
  return types[name], nil
}

func (this *LogicalPermissions) GetTypes() map[string]func(string, map[string]interface{}) (bool, error) {
  if this.types == nil {
    this.types = make(map[string]func(string, map[string]interface{}) bool)
  }
  types := make(map[string]func(string, map[string]interface{}) bool)
  for name, callback := range this.types {
    types[name] = callback
  }
  return types
}

func (this *LogicalPermissions) SetTypes(types map[string]func(string, map[string]interface{}) (bool, error)) error {
  for name, _ := range types {
    if name == "" {
      return &InvalidArgumentValueError{"The name parameter cannot be empty."}
    }
  }

  this.types = make(map[string]func(string, map[string]interface{}) bool)
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
  access := false
  allow_bypass := false
  var permissions map[string]interface{}
  err := json.Unmarshal([]byte(json_permissions), &permissions)
  if err != nil {
    err = &err.(type){fmt.Sprintf("Error parsing json_permissions: %s"), err}
    return false, err
  }
  if val, ok := permissions["no_bypass"]; ok {
    switch val.(type) {
      case bool:
        allow_bypass = !permissions["no_bypass"]
      case map[string]interface{}:
        allow_bypass, err = !this.processOR(permissions.no_bypass, nil, context)
        if err != nil {
          err = &err.(type){fmt.Sprintf("Error checking no_bypass permissions: %s"), err}
          return false, err
        }
      default:
        return false, &InvalidArgumentValueError{fmt.Sprintf("The no_bypass value must be a boolean or a map. Current value: %v", val)}
    }
    delete(permissions["no_bypass"])
    
    if allow_bypass {
    access, err = this.checkBypassAccess(context)
      if err != nil {
        err = &err.(type){fmt.Sprintf("Error checking bypass access: %s"), err}
        return false, err
      }
    }
    if !access {
      if len(permissions) > 0 {
        access, err = this.processOR(permissions, nil, context)
        if err != nil {
          err = &err.(type){fmt.Sprintf("Error checking access: %s"), err}
          return false, err
        }
      }
    }
  }
  return access, nil
}

func (this *LogicalPermissions) dispatch(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  access := false
  err := make(error)
  switch permissions.(type) {
    case string:
      access, err = externalAccessCheck(permissions, type, context)
      if err != nil {
        return false, err
      }
    case []interface{}:
      if len(permissions) > 0 {
        access, err = this.processOR(permissions, type, context) 
        if err != nil {
          return false, err
        }
      }
    case map[string]interface{}:
      if len(permissions) == 1 {
        key := ""
        for k, _ := range permissions {
          key = k
          break
        }
        value := permissions[key]
        if key == "AND" {
          access, err = this.processAND(value, type, context)
          if err != nil {
            return false, err
          }
        }
        else if key == "NAND" {
          access, err = this.processNAND(value, type, context)
          if err != nil {
            return false, err
          }
        }
        else if key == "OR" {
          access, err = this.processOR(value, type, context)
          if err != nil {
            return false, err
          }
        }
        else if key == "NOR" {
          access, err = this.processNOR(value, type, context)
          if err != nil {
            return false, err
          }
        }
        else if key == "XOR" {
          access, err = this.processXOR(value, type, context)
          if err != nil {
            return false, err
          }
        }
        else if key == "NOT" {
          access, err = this.processNOT(value, type, context)
          if err != nil {
            return false, err
          }
        }
        else {
          if _, err2 := strconv.Atoi(v); err2 == nil {
            if type == nil {
              type = key 
            }
            else {
              return false, &InvalidArgumentValueError{fmt.Sprintf("You cannot put a permission type as a descendant to another permission type. Existing type: %s. Evaluated permissions: %v", type, permissions)}
            }
          }
          if value.(type) == []interface{} || value.(type) == map[string]interface{} {
            access, err = this.processOR(value, type, context)
            if err != nil {
              return false, err
            }
          }
          else {
            access, err = this.dispatch(value, type, context)
            if err != nil {
              return false, err
            }
          }
        }
      }s
      else if len(permissions) > 1 {
        access, err = this.processOR(permissions, type, context) 
        if err != nil {
          return false, err
        }
      }
    default:
      return false, &InvalidArgumentValueError{fmt.Sprintf("A permission value must either be a string, a slice or an map. Evaluated permissions: %v", permissions)}
  }
  return access, nil
}

func (this *LogicalPermissions) processAND(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  access := false
  if permissions.(type) == []interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value slice of an AND gate must contain a minimum of one element. Current value: %v", permissions)}
    }
    
    access = true
    for _, permission := range permissions {
      tmp, err := this.dispatch(permission, type, context)
      if err != nil {
        return false, err
      }
      access = access && tmp
      if !access {
        break 
      }
    }
  }
  else if permissions.(type) == map[string]interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value map of an AND gate must contain a minimum of one element. Current value: %v", permissions)}
    }
    
    access = true
    for k, v := range permissions {
      subpermissions := map[string]interface{}{k: v}
      tmp, err := this.dispatch(subpermissions, type, context)
      if err != nil {
        return false, err
      }
      access = access && tmp
      if !access {
        break 
      }
    }
  }
  else {
    return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value of an AND gate must be a slice or map. Current value: %v", permissions)}
  }
  return access, nil
}

func (this *LogicalPermissions) processNAND(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  if permissions.(type) == []interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value slice of a NAND gate must contain a minimum of one element. Current value: %v", permissions)}
    }
  }
  else if permissions.(type) == map[string]interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value map of a NAND gate must contain a minimum of one element. Current value: %v", permissions)}
    }
  }
  else {
    return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value of a NAND gate must be a slice or map. Current value: %v", permissions)}
  }
  
  access, err := !this.processAND(permissions, type, context)
  if err != nil {
    return false, err
  }
  return access
}

func (this *LogicalPermissions) processOR(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  access := false
  if permissions.(type) == []interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value slice of an OR gate must contain a minimum of one element. Current value: %v", permissions)}
    }

    for _, permission := range permissions {
      tmp, err := this.dispatch(permission, type, context)
      if err != nil {
        return false, err
      }
      access = access || tmp
      if access {
        break 
      }
    }
  }
  else if permissions.(type) == map[string]interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value map of an OR gate must contain a minimum of one element. Current value: %v", permissions)}
    }

    for k, v := range permissions {
      subpermissions := map[string]interface{}{k: v}
      tmp, err := this.dispatch(subpermissions, type, context)
      if err != nil {
        return false, err
      }
      access = access || tmp
      if access {
        break 
      }
    }
  }
  else {
    return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value of an OR gate must be a slice or map. Current value: %v", permissions)}
  }
  return access, nil
}

func (this *LogicalPermissions) processNOR(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  if permissions.(type) == []interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value slice of a NOR gate must contain a minimum of one element. Current value: %v", permissions)}
    }
  }
  else if permissions.(type) == map[string]interface{} {
    if len(permissions) < 1 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value map of a NOR gate must contain a minimum of one element. Current value: %v", permissions)}
    }
  }
  else {
    return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value of a NOR gate must be a slice or map. Current value: %v", permissions)}
  }
  
  access, err := !this.processOR(permissions, type, context)
  if err != nil {
    return false, err
  }
  return access
}

func (this *LogicalPermissions) processXOR(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  access := false
  count_true := 0
  count_false := 0
  if permissions.(type) == []interface{} {
    if len(permissions) < 2 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value slice of an XOR gate must contain a minimum of two elements. Current value: %v", permissions)}
    }
    
    for _, permission := range permissions {
      tmp, err := this.dispatch(permission, type, context)
      if err != nil {
        return false, err
      }
      if tmp {
        count_true++ 
      }
      else {
        count_false++ 
      }
      if count_true > 0 && count_false > 0 {
        access = true
        break
      }
    }
  }
  else if permissions.(type) == map[string]interface{} {
    if len(permissions) < 2 {
      return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value map of an XOR gate must contain a minimum of two elements. Current value: %v", permissions)}
    }
    
    for k, v := range permissions {
      subpermissions := map[string]interface{}{k: v}
      tmp, err := this.dispatch(subpermissions, type, context)
      if err != nil {
        return false, err
      }
      if tmp {
        count_true++ 
      }
      else {
        count_false++ 
      }
      if count_true > 0 && count_false > 0 {
        access = true
        break
      }
    }
  }
  else {
    return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value of an XOR gate must be a slice or map. Current value: %v", permissions)}
  }
}

func (this *LogicalPermissions) processNOT(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  if permissions.(type) == map[string]interface{} {
    if len(permissions) != 1 {
      return false, &InvalidValueForLogicGateError(fmt.Sprintf("A NOT permission must have exactly one child in the value map. Current value: %v", permissions))
    }
  }
  else if permissions.(type) == string {
    if permissions == "" {
      return false, &InvalidValueForLogicGateError{"A NOT permission cannot have an empty string as its value."}
    }
  }
  else {
    return false, &InvalidValueForLogicGateError{fmt.Sprintf("The value of a NOT gate must be a map or string. Current value: %v", permissions)}
  }
  
  access, err := !this.dispatch(permissions, type, context)
  if err != nil {
    return false, err
  }
  return access
}

func (this *LogicalPermissions) externalAccessCheck(permission string, type string, context map[string]interface{}) (bool, error) {
  exists, err := this.TypeExists(type)
  if err != nil {
    return false, err
  }
  if !exists {
    return false, &PermissionTypeNotRegisteredException{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::addType() or LogicalPermissions::setTypes() to register permission types.", type)}
  }
  
  callback := this.GetTypeCallback(type)
  access, err2 := callback(permission, context)
  if err2 != nil {
    return false, err2 
  }
  return access, nil
}