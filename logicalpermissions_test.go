package logicalpermissions_test

import (
  "testing"
  "github.com/stretchr/testify/assert"
  . "github.com/ordermind/logical-permissions-go"
)

func TestCreation(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  var i interface{} = &lp
  _, ok := i.(LogicalPermissionsInterface)
  assert.True(t, ok)
}
