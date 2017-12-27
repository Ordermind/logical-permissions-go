package logicalpermissions_test

import (
	"fmt"
	"sort"
	"testing"

	. "github.com/ordermind/logical-permissions-go"
	"github.com/stretchr/testify/assert"
)

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func TestCreation(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	var i interface{} = &lp
	_, ok := i.(LogicalPermissionsInterface)
	assert.True(t, ok, "LogicalPermissions is not implementing LogicalPermissionsInterface correctly.")
}

/*-----------LogicalPermissions::AddType()-------------*/

func TestAddTypeParamNameEmpty(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("", type_callback)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestAddTypeParamNameIsCoreKey(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("AND", type_callback)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestAddTypeParamNameExists(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("test", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	err2 := lp.AddType("test", type_callback)
	if assert.Error(t, err2) {
		assert.IsType(t, &PermissionTypeAlreadyExistsError{}, err2)
	}
}

func TestAddType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("test", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	exists, err2 := lp.TypeExists("test")
	if err2 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::TypeExists() returned an error: %s", err2))
	}
	assert.True(t, exists)
}

/*-----------LogicalPermissions::RemoveType()-------------*/

func TestRemoveTypeParamNameEmpty(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	err := lp.RemoveType("")
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestRemoveTypeUnregisteredType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	err := lp.RemoveType("test")
	if assert.Error(t, err) {
		assert.IsType(t, &PermissionTypeNotRegisteredError{}, err)
	}
}

func TestRemoveType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("test", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	err2 := lp.RemoveType("test")
	if err2 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::RemoveType() returned an error: %s", err2))
	}
	exists, err3 := lp.TypeExists("test")
	if err3 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::TypeExists() returned an error: %s", err3))
	}
	assert.False(t, exists)
}

/*-------------LogicalPermissions::TypeExists()--------------*/

func TestTypeExistsParamNameEmpty(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	_, err := lp.TypeExists("")
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestTypeExists(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("test", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	exists, err2 := lp.TypeExists("test")
	if err2 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::TypeExists() returned an error: %s", err2))
	}
	assert.True(t, exists)
}

/*-------------LogicalPermissions::GetTypeCallback()--------------*/

func TestGetTypeCallbackParamNameEmpty(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	_, err := lp.GetTypeCallback("")
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestGetTypeCallbackUnregisteredType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	_, err := lp.GetTypeCallback("test")
	if assert.Error(t, err) {
		assert.IsType(t, &PermissionTypeNotRegisteredError{}, err)
	}
}

func TestGetTypeCallback(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback1 := func(string, map[string]interface{}) (bool, error) {
		return true, nil
	}
	err := lp.AddType("test", callback1)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	callback2, err2 := lp.GetTypeCallback("test")
	if err2 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::GetTypeCallback() returned an error: %s", err2))
	}
	callback1_sig = fmt.Sprintf("%v", callback1)
  callback2_sig = fmt.Sprintf("%v", callback2)
	assert.Equal(t, callback1_sig, callback2_sig)
}

/*-------------LogicalPermissions::SetTypeCallback()--------------*/

func TestSetTypeCallbackParamNameEmpty(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.SetTypeCallback("", callback)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestSetTypeCallbackUnregisteredType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.SetTypeCallback("test", callback)
	if assert.Error(t, err) {
		assert.IsType(t, &PermissionTypeNotRegisteredError{}, err)
	}
}

func TestSetTypeCallback(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	err := lp.AddType("test", func(string, map[string]interface{}) (bool, error) { return true, nil })
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	callback := func(string, map[string]interface{}) (bool, error) { return true, nil }

	callback2, err2 := lp.GetTypeCallback("test")
	if err2 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::GetTypeCallback() returned an error: %s", err2))
	}

	assert.NotEqual(t, fmt.Sprintf("%v", callback), fmt.Sprintf("%v", callback2))

	err3 := lp.SetTypeCallback("test", callback)
	if err3 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::SetTypeCallback() returned an error: %s", err3))
	}

	callback3, err4 := lp.GetTypeCallback("test")
	if err4 != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::GetTypeCallback() returned an error: %s", err4))
	}
	assert.Equal(t, fmt.Sprintf("%v", callback), fmt.Sprintf("%v", callback3))
}

/*-------------LogicalPermissions::GetTypes()--------------*/

func TestGetTypes(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	assert.Equal(t, lp.GetTypes(), make(map[string]func(string, map[string]interface{}) (bool, error)))
	callback := func(string, map[string]interface{}) (bool, error) {
		return true, nil
	}
	err := lp.AddType("test", callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	types := lp.GetTypes()
	assert.Equal(t, fmt.Sprintf("%v", map[string]func(string, map[string]interface{}) (bool, error){"test": callback}), fmt.Sprintf("%v", types))
	types["test2"] = callback
	if _, ok := lp.GetTypes()["test2"]; ok {
		t.Error("lp.GetTypes() contains \"test2\" key")
	}
}

/*-------------LogicalPermissions::SetTypes()--------------*/

func TestSetTypesParamNameEmpty(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback := func(string, map[string]interface{}) (bool, error) {
		return true, nil
	}
	types := map[string]func(string, map[string]interface{}) (bool, error){"": callback}
	err := lp.SetTypes(types)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestSetTypesParamTypesNameIsCoreKey(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback := func(string, map[string]interface{}) (bool, error) {
		return true, nil
	}
	types := map[string]func(string, map[string]interface{}) (bool, error){"AND": callback}
	err := lp.SetTypes(types)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestSetTypes(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback := func(string, map[string]interface{}) (bool, error) {
		return true, nil
	}
	types := map[string]func(string, map[string]interface{}) (bool, error){"test": callback}
	err := lp.SetTypes(types)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::SetTypes() returned an error: %s", err))
	}
	assert.Equal(t, fmt.Sprintf("%v", types), fmt.Sprintf("%v", lp.GetTypes()))
	types["test2"] = callback
	if _, ok := lp.GetTypes()["test2"]; ok {
		t.Error("lp.GetTypes() contains \"test2\" key")
	}
}

/*-------------LogicalPermissions::GetBypassCallback()--------------*/

func TestGetBypassCallback(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	assert.Nil(t, lp.GetBypassCallback())
}

/*-------------LogicalPermissions::SetBypassCallback()--------------*/

func TestSetBypassCallback(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	callback := func(map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(callback)
	assert.Equal(t, fmt.Sprintf("%v", callback), fmt.Sprintf("%v", lp.GetBypassCallback()))
}

/*------------LogicalPermissions::getValidPermissionKeys()------------*/

func TestGetValidPermissionKeys(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	keys := lp.GetValidPermissionKeys()
	sort.Strings(keys)
	keys2 := []string{"NO_BYPASS", "AND", "NAND", "OR", "NOR", "XOR", "NOT", "TRUE", "FALSE"}
	sort.Strings(keys2)
	assert.Equal(t, keys, keys2)
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "testflag" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					testflag, ok := typed_user["testflag"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := testflag.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
		"misc": func(item string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				item_value, ok := typed_user[item]
				if !ok {
					return false, nil
				}
				if typed_item_value, ok := item_value.(bool); ok {
					return typed_item_value, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	keys3 := lp.GetValidPermissionKeys()
	sort.Strings(keys3)
	keys4 := []string{"NO_BYPASS", "AND", "NAND", "OR", "NOR", "XOR", "NOT", "TRUE", "FALSE", "flag", "role", "misc"}
	sort.Strings(keys4)
	assert.Equal(t, keys3, keys4)
}

/*-------------LogicalPermissions::CheckAccess()--------------*/

func TestCheckAccessParamPermissionsWrongPermissionType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	permissions := 50
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &CustomError{}, err)
	}

	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err = lp.AddType("flag", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}

	int_permissions := `{
    "flag": 1
  }`
	access, err = lp.CheckAccess(int_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	str_permissions := `
    "flag": "testflag"
  `
	access, err = lp.CheckAccess(str_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	callback := func(map[string]interface{}) (bool, error) {
		return true, nil
	}
	func_permissions := map[string]interface{}{
		"test": callback,
	}
	access, err = lp.CheckAccess(func_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessParamPermissionsNestedTypes(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("flag", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}

	//Directly nested
	permissions := `{
    "flag": {
      "flag": "testflag"
    }
  }`
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	//Indirectly nested
	permissions = `{
    "flag": {
      "OR": {
        "flag": "testflag"
      }
    }
  }`
	access, err = lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessParamPermissionsUnregisteredType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	permissions := `{
    "flag": "testflag"
  }`
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &PermissionTypeNotRegisteredError{}, err)
	}
}

func TestCheckAccessEmptyMapAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	access, err := lp.CheckAccess(make(map[string]interface{}), make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBypassAccessCheckContextPassing(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	user := map[string]interface{}{
		"id": 1,
	}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		_, ok := context["user"]
		assert.True(t, ok)
		assert.Equal(t, user, context["user"])
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	lp.CheckAccess(false, map[string]interface{}{"user": user})
}

func TestCheckAccessBypassAccessIllegalDescendant(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	permissions := map[string]interface{}{
		"OR": map[string]interface{}{
			"no_bypass": true,
		},
	}
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessBypassAccessAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	access, err := lp.CheckAccess(false, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBypassAccessDeny(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return false, nil
	}
	lp.SetBypassCallback(bypass_callback)
	access, err := lp.CheckAccess(false, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBypassAccessDeny2(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	access, err := lp.CheckAccessNoBypass(false, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassWrongType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	access, err := lp.CheckAccess(map[string]interface{}{"no_bypass": []string{"test"}}, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessNoBypassEmptyPermissionsAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	access, err := lp.CheckAccess(map[string]interface{}{"no_bypass": true}, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassWrongValue(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("test", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": map[string]interface{}{
			"test": true,
		},
	}
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessNoBypassAccessBooleanAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": false,
	}
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
	//Test that permission object is not changed
	_, ok := permissions["no_bypass"]
	assert.True(t, ok)
}

func TestCheckAccessNoBypassAccessBooleanDeny(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": true,
		"0":         false,
	}
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassAccessStringAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": "False",
	}
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
	//Test that permission object is not changed
	_, ok := permissions["no_bypass"]
	assert.True(t, ok)
}

func TestCheckAccessNoBypassAccessStringDeny(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": "True",
		"0":         "FALSE",
	}
	access, err := lp.CheckAccess(permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassAccessMapAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "never_bypass" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					never_bypass, ok := typed_user["never_bypass"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := never_bypass.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": map[string]interface{}{
			"flag": "never_bypass",
		},
	}
	user := map[string]interface{}{
		"id":           1,
		"never_bypass": false,
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassAccessJSONAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "never_bypass" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					never_bypass, ok := typed_user["never_bypass"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := never_bypass.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := `{
    "no_bypass": {
      "flag": "never_bypass"
    }
  }`
	user := map[string]interface{}{
		"id":           1,
		"never_bypass": false,
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassAccessMapDeny(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "never_bypass" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					never_bypass, ok := typed_user["never_bypass"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := never_bypass.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := map[string]interface{}{
		"no_bypass": map[string]interface{}{
			"flag": "never_bypass",
		},
		"0": false,
	}
	user := map[string]interface{}{
		"id":           1,
		"never_bypass": true,
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNoBypassAccessJSONDeny(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "never_bypass" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					never_bypass, ok := typed_user["never_bypass"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := never_bypass.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)
	permissions := `{
    "no_bypass": {
      "flag": "never_bypass"
    },
    "0": false
  }`
	user := map[string]interface{}{
		"id":           1,
		"never_bypass": true,
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessSingleItemAllow(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "testflag" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					testflag, ok := typed_user["testflag"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := testflag.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := `{
    "no_bypass": {
      "flag": "never_bypass"
    },
    "flag": "testflag"
  }`
	user := map[string]interface{}{
		"id":       1,
		"testflag": true,
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessSingleItemDeny(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "testflag" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					testflag, ok := typed_user["testflag"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := testflag.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := `{
    "no_bypass": {
      "flag": "never_bypass"
    },
    "flag": "testflag"
  }`
	user := map[string]interface{}{
		"id": 1,
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessMultipleTypesShorthandOR(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"flag": func(flag string, context map[string]interface{}) (bool, error) {
			if flag == "testflag" {
				user, ok := context["user"]
				if !ok {
					return false, nil
				}
				if typed_user, ok := user.(map[string]interface{}); ok {
					testflag, ok := typed_user["testflag"]
					if !ok {
						return false, nil
					}
					if bool_never_bypass, ok := testflag.(bool); ok {
						access := bool_never_bypass
						return access, nil
					}
				}
			}
			return false, nil
		},
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
		"misc": func(item string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				item_value, ok := typed_user[item]
				if !ok {
					return false, nil
				}
				if typed_item_value, ok := item_value.(bool); ok {
					return typed_item_value, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := `{
    "no_bypass": {
      "flag": "never_bypass"
    },
    "flag": "testflag",
    "role": "admin",
    "misc": "test"
  }`
	user := map[string]interface{}{
		"id": 1,
	}

	//OR truth table
	//0 0 0
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)
	//0 0 1
	user["test"] = true
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//0 1 0
	user["test"] = false
	user["roles"] = []string{"admin"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//0 1 1
	user["test"] = true
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//1 0 0
	user = map[string]interface{}{
		"id":       1,
		"testflag": true,
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//1 0 1
	user["test"] = true
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//1 1 0
	user["test"] = false
	user["roles"] = []string{"admin"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//1 1 1
	user["test"] = true
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessMultipleItemsShorthandOR(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": []string{
			"admin",
			"editor",
		},
	}
	user := map[string]interface{}{
		"id": 1,
	}
	//OR truth table
	//0 0
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)
	user["roles"] = []string{}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)
	//0 1
	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//1 0
	user["roles"] = []string{"admin"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
	//1 1
	user["roles"] = []string{"editor", "admin"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessANDWrongValueType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"AND": "admin",
		},
	}
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessANDTooFewElements(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"AND": []string{},
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}

	permissions = map[string]interface{}{
		"role": map[string]interface{}{
			"AND": map[string]interface{}{},
		},
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessMultipleItemsAND(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	runTruthTable := func(permissions interface{}) {
		user := map[string]interface{}{
			"id": 1,
		}
		//AND truth table
		//0 0 0
		access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		user["roles"] = []string{}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 0 1
		user["roles"] = []string{"writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 1 0
		user["roles"] = []string{"editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 1 1
		user["roles"] = []string{"editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 0 0
		user["roles"] = []string{"admin"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 0 1
		user["roles"] = []string{"admin", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 1 0
		user["roles"] = []string{"admin", "editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 1 1
		user["roles"] = []string{"admin", "editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
	}

	permissions := `{
    "role": {
      "AND": [
        "admin",
        "editor",
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "AND": {
        "0": "admin",
        "1": "editor",
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "AND": [
        ["admin"],
        {"0": "editor"},
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "AND": {
        "0": ["admin"],
        "1": {"0": "editor"},
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)
}

func TestCheckAccessNANDWrongValueType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NAND": "admin",
		},
	}
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessNANDTooFewElements(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NAND": []string{},
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}

	permissions = map[string]interface{}{
		"role": map[string]interface{}{
			"NAND": map[string]interface{}{},
		},
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessMultipleItemsNAND(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	runTruthTable := func(permissions interface{}) {
		user := map[string]interface{}{
			"id": 1,
		}
		//NAND truth table
		//0 0 0
		access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		user["roles"] = []string{}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 0 1
		user["roles"] = []string{"writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 1 0
		user["roles"] = []string{"editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 1 1
		user["roles"] = []string{"editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 0 0
		user["roles"] = []string{"admin"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 0 1
		user["roles"] = []string{"admin", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 1 0
		user["roles"] = []string{"admin", "editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 1 1
		user["roles"] = []string{"admin", "editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
	}

	permissions := `{
    "role": {
      "NAND": [
        "admin",
        "editor",
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "NAND": {
        "0": "admin",
        "1": "editor",
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "NAND": [
        ["admin"],
        {"0": "editor"},
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "NAND": {
        "0": ["admin"],
        "1": {"0": "editor"},
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)
}

func TestCheckAccessORWrongValueType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"OR": "admin",
		},
	}
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessORTooFewElements(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"OR": []string{},
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}

	permissions = map[string]interface{}{
		"role": map[string]interface{}{
			"OR": map[string]interface{}{},
		},
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessMultipleItemsOR(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	runTruthTable := func(permissions interface{}) {
		user := map[string]interface{}{
			"id": 1,
		}
		//OR truth table
		//0 0 0
		access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		user["roles"] = []string{}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 0 1
		user["roles"] = []string{"writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 1 0
		user["roles"] = []string{"editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 1 1
		user["roles"] = []string{"editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 0 0
		user["roles"] = []string{"admin"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 0 1
		user["roles"] = []string{"admin", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 1 0
		user["roles"] = []string{"admin", "editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 1 1
		user["roles"] = []string{"admin", "editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
	}

	permissions := `{
    "role": {
      "OR": [
        "admin",
        "editor",
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "OR": {
        "0": "admin",
        "1": "editor",
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "OR": [
        ["admin"],
        {"0": "editor"},
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "OR": {
        "0": ["admin"],
        "1": {"0": "editor"},
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)
}

func TestCheckAccessNORWrongValueType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOR": "admin",
		},
	}
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessNORTooFewElements(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOR": []string{},
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}

	permissions = map[string]interface{}{
		"role": map[string]interface{}{
			"NOR": map[string]interface{}{},
		},
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessMultipleItemsNOR(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	runTruthTable := func(permissions interface{}) {
		user := map[string]interface{}{
			"id": 1,
		}
		//NOR truth table
		//0 0 0
		access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		user["roles"] = []string{}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 0 1
		user["roles"] = []string{"writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 1 0
		user["roles"] = []string{"editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 1 1
		user["roles"] = []string{"editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 0 0
		user["roles"] = []string{"admin"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 0 1
		user["roles"] = []string{"admin", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 1 0
		user["roles"] = []string{"admin", "editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//1 1 1
		user["roles"] = []string{"admin", "editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
	}

	permissions := `{
    "role": {
      "NOR": [
        "admin",
        "editor",
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "NOR": {
        "0": "admin",
        "1": "editor",
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "NOR": [
        ["admin"],
        {"0": "editor"},
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "NOR": {
        "0": ["admin"],
        "1": {"0": "editor"},
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)
}

func TestCheckAccessXORWrongValueType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"XOR": "admin",
		},
	}
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessXORTooFewElements(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"XOR": []string{"admin"},
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}

	permissions = map[string]interface{}{
		"role": map[string]interface{}{
			"XOR": map[string]interface{}{"0": "admin"},
		},
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessMultipleItemsXOR(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	runTruthTable := func(permissions interface{}) {
		user := map[string]interface{}{
			"id": 1,
		}
		//XOR truth table
		//0 0 0
		access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		user["roles"] = []string{}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
		//0 0 1
		user["roles"] = []string{"writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 1 0
		user["roles"] = []string{"editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//0 1 1
		user["roles"] = []string{"editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 0 0
		user["roles"] = []string{"admin"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 0 1
		user["roles"] = []string{"admin", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 1 0
		user["roles"] = []string{"admin", "editor"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.True(t, access)
		assert.Nil(t, err)
		//1 1 1
		user["roles"] = []string{"admin", "editor", "writer"}
		access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
		assert.False(t, access)
		assert.Nil(t, err)
	}

	permissions := `{
    "role": {
      "XOR": [
        "admin",
        "editor",
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "XOR": {
        "0": "admin",
        "1": "editor",
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "XOR": [
        ["admin"],
        {"0": "editor"},
        "writer"
      ]
    }
  }`
	runTruthTable(permissions)

	permissions = `{
    "role": {
      "XOR": {
        "0": ["admin"],
        "1": {"0": "editor"},
        "2": "writer"
      }
    }
  }`
	runTruthTable(permissions)
}

func TestCheckAccessNOTWrongValueType(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOT": true,
		},
	}
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessNOTTooFewElements(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)
	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOT": "",
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}

	permissions = map[string]interface{}{
		"role": map[string]interface{}{
			"NOT": map[string]interface{}{},
		},
	}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessMultipleItemsNOT(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOT": map[string]interface{}{"0": "admin", "1": "editor"},
		},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{})
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidValueForLogicGateError{}, err)
	}
}

func TestCheckAccessSingleItemNOTString(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOT": "admin",
		},
	}

	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin", "editor"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	delete(user, "roles")
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessSingleItemNOTMapJSON(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	map_permissions := map[string]interface{}{
		"role": map[string]interface{}{
			"NOT": map[string]interface{}{"5": "admin"},
		},
	}

	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin", "editor"},
	}
	access, err := lp.CheckAccess(map_permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	delete(user, "roles")
	access, err = lp.CheckAccess(map_permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(map_permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	json_permissions := `{
    "role": {
      "NOT": {"5": "admin"}
    }
  }`

	user = map[string]interface{}{
		"id":    1,
		"roles": []string{"admin", "editor"},
	}
	access, err = lp.CheckAccess(json_permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	delete(user, "roles")
	access, err = lp.CheckAccess(json_permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(json_permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBoolTRUEIllegalDescendant(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("role", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}

	map_permissions := map[string]interface{}{
		"role": [1]interface{}{true},
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions := `{
    "role": [true]
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessBoolTRUE(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	bool_permissions := true
	access, err := lp.CheckAccess(bool_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBoolTRUESlice(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	slice_permissions := []interface{}{true}
	access, err := lp.CheckAccess(slice_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)

	json_permissions := "[true]"
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBoolFALSEIllegalDescendant(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("role", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}

	map_permissions := map[string]interface{}{
		"role": [1]interface{}{false},
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions := `{
    "role": [false]
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessBoolFALSE(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	bool_permissions := false
	access, err := lp.CheckAccess(bool_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBoolFALSESlice(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	slice_permissions := []interface{}{false}
	access, err := lp.CheckAccess(slice_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)

	str_permissions := "[false]"
	access, err = lp.CheckAccess(str_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBoolFALSEBypass(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)

	bool_permissions := false
	access, err := lp.CheckAccess(bool_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessBoolFALSENoBypass(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)

	map_permissions := map[string]interface{}{
		"no_bypass": true,
		"0":         false,
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)

	json_permissions := `{
    "no_bypass": true,
    "0": false
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessStringTRUEIllegalChildren(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	map_permissions := map[string]interface{}{
		"TRUE": false,
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	map_permissions = map[string]interface{}{
		"TRUE": make([]interface{}, 0),
	}
	access, err = lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions := `{
    "TRUE": false
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions = `{
    "TRUE": []
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessStringTRUEIllegalDescendant(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("role", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}

	map_permissions := map[string]interface{}{
		"role": [1]interface{}{"TRUE"},
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions := `{
    "role": ["TRUE"]
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessStringTRUE(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	str_permissions := "TRUE"
	access, err := lp.CheckAccess(str_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessStringTRUESlice(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	slice_permissions := []interface{}{"TRUE"}
	access, err := lp.CheckAccess(slice_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)

	json_permissions := `[
    "TRUE"
  ]`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessStringFALSEIllegalChildren(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	map_permissions := map[string]interface{}{
		"FALSE": true,
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	map_permissions = map[string]interface{}{
		"FALSE": make([]interface{}, 0),
	}
	access, err = lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions := `{
    "FALSE": true
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions = `{
    "FALSE": []
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessStringFALSEIllegalDescendant(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	type_callback := func(string, map[string]interface{}) (bool, error) { return true, nil }
	err := lp.AddType("role", type_callback)
	if err != nil {
		t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
	}

	map_permissions := map[string]interface{}{
		"role": [1]interface{}{"FALSE"},
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}

	json_permissions := `{
    "role": ["FALSE"]
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	if assert.Error(t, err) {
		assert.IsType(t, &InvalidArgumentValueError{}, err)
	}
}

func TestCheckAccessStringFALSE(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	str_permissions := "FALSE"
	access, err := lp.CheckAccess(str_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessStringFALSESlice(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	slice_permissions := []interface{}{"FALSE"}
	access, err := lp.CheckAccess(slice_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)

	json_permissions := `[
    "FALSE"
  ]`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessStringFALSEBypass(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)

	str_permissions := "FALSE"
	access, err := lp.CheckAccess(str_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessStringFALSENoBypass(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	bypass_callback := func(context map[string]interface{}) (bool, error) {
		return true, nil
	}
	lp.SetBypassCallback(bypass_callback)

	map_permissions := map[string]interface{}{
		"no_bypass": true,
		"0":         "FALSE",
	}
	access, err := lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)

	json_permissions := `{
    "no_bypass": true,
    "0": "FALSE"
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestMixedBooleans(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}

	slice_permissions := []interface{}{"FALSE", true}
	access, err := lp.CheckAccess(slice_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)

	json_permissions := `[
    "FALSE",
    true
  ]`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)

	map_permissions := map[string]interface{}{
		"OR": []interface{}{
			false,
			"TRUE",
		},
	}
	access, err = lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)

	json_permissions = `{
    "OR": [
      false,
      "TRUE"
    ]
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.True(t, access)
	assert.Nil(t, err)

	map_permissions = map[string]interface{}{
		"AND": []interface{}{
			"TRUE",
			false,
		},
	}
	access, err = lp.CheckAccess(map_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)

	json_permissions = `{
    "AND": [
      "TRUE",
      false
    ]
  }`
	access, err = lp.CheckAccess(json_permissions, make(map[string]interface{}))
	assert.False(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessNestedLogic(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	permissions := `
  {
    "role": {
      "OR": {
        "NOT": {
          "AND": [
            "admin",
            "editor"
          ]
        }
      }
    },
    "0": false,
    "1": "FALSE"
  }`

	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin", "editor"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	delete(user, "roles")
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessLogicGateFirst(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	permissions := `
  {
    "AND": {
      "role": {
        "OR": {
          "NOT": {
            "AND": [
              "admin",
              "editor"
            ]
          }
        }
      },
      "0": true,
      "1": "TRUE"
    }
  }`

	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin", "editor"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	delete(user, "roles")
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}

func TestCheckAccessShorthandORMixedObjectsArrays(t *testing.T) {
	t.Parallel()
	lp := LogicalPermissions{}
	types := map[string]func(string, map[string]interface{}) (bool, error){
		"role": func(role string, context map[string]interface{}) (bool, error) {
			user, ok := context["user"]
			if !ok {
				return false, nil
			}
			if typed_user, ok := user.(map[string]interface{}); ok {
				roles, ok := typed_user["roles"]
				if !ok {
					return false, nil
				}
				if typed_roles, ok := roles.([]string); ok {
					has_role := stringInSlice(role, typed_roles)
					return has_role, nil
				}
			}
			return false, nil
		},
	}
	err := lp.SetTypes(types)
	assert.Nil(t, err)

	permissions := `
  {
    "role": [
      "admin",
      {
        "AND": [
          "editor",
          "writer",
          {
            "OR": [
              "role1",
              "role2"
            ]
          }
        ]
      }
    ]
  }`

	user := map[string]interface{}{
		"id":    1,
		"roles": []string{"admin"},
	}
	access, err := lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	delete(user, "roles")
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor", "writer"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.False(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor", "writer", "role1"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"editor", "writer", "role2"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)

	user["roles"] = []string{"admin", "writer"}
	access, err = lp.CheckAccess(permissions, map[string]interface{}{"user": user})
	assert.True(t, access)
	assert.Nil(t, err)
}
