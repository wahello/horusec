// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package requirements

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateRequirements(t *testing.T) {
	t.Run("should return no error when everything it is ok", func(t *testing.T) {
		controller := NewRequirements()

		assert.NotPanics(t, func() {
			controller.ValidateDocker()
		})
		assert.NotPanics(t, func() {
			controller.ValidateGit()
		})
	})
}