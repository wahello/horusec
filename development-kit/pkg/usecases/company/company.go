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

package company

import (
	"encoding/json"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"io"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
)

type ICompany interface {
	NewAccountCompanyFromReadCLoser(body io.ReadCloser) (accountCompany *roles.AccountCompany, err error)
	NewCompanyFromReadCloser(body io.ReadCloser) (company *accountEntities.Company, err error)
	CheckCreateCompanyErrors(err error) error
}

type Company struct {
}

func NewCompanyUseCases() ICompany {
	return &Company{}
}

func (c *Company) NewAccountCompanyFromReadCLoser(body io.ReadCloser) (
	accountCompany *roles.AccountCompany, err error) {
	err = json.NewDecoder(body).Decode(&accountCompany)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return accountCompany, accountCompany.Validate()
}

func (c *Company) NewCompanyFromReadCloser(body io.ReadCloser) (company *accountEntities.Company, err error) {
	err = json.NewDecoder(body).Decode(&company)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return company, company.Validate()
}

func (c *Company) CheckCreateCompanyErrors(err error) error {
	if err.Error() == "pq: duplicate key value violates unique constraint \"uk_companies_username\"" {
		return errorsEnum.ErrorCompanyNameAlreadyInUse
	}

	return err
}