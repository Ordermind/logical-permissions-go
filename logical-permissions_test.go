package logicalpermissions

import (
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestCreation(t *testing.T) {
  lp := LogicalPermissions{}
  var i interface{} = &lp
  _, ok := i.(LogicalPermissionsInterface)
  assert.True(t, ok)
}
