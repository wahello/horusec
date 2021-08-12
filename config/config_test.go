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

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
)

func TestDefaultConfig(t *testing.T) {
	wd, err := os.Getwd()
	require.Nil(t, err)

	config := New()
	assert.Equal(t, "{{VERSION_NOT_FOUND}}", config.Version)
	assert.Equal(t, filepath.Join(wd, "horusec-config.json"), config.ConfigFilePath)
	assert.Equal(t, "http://0.0.0.0:8000", config.HorusecAPIUri)
	assert.Equal(t, int64(300), config.TimeoutInSecondsRequest)
	assert.Equal(t, int64(600), config.TimeoutInSecondsAnalysis)
	assert.Equal(t, int64(15), config.MonitorRetryInSeconds)
	assert.Equal(t, uuid.Nil.String(), config.RepositoryAuthorization)
	assert.Equal(t, "", config.PrintOutputType)
	assert.Equal(t, "", config.JSONOutputFilePath)
	assert.Equal(t, 1, len(config.SeveritiesToIgnore))
	assert.Equal(t, 2, len(config.FilesOrPathsToIgnore))
	assert.Equal(t, false, config.ReturnErrorIfFoundVulnerability)
	assert.Equal(t, wd, config.ProjectPath)
	assert.Equal(t, workdir.NewWorkDir(), config.WorkDir)
	assert.Equal(t, false, config.EnableGitHistoryAnalysis)
	assert.Equal(t, false, config.CertInsecureSkipVerify)
	assert.Equal(t, "", config.CertPath)
	assert.Equal(t, false, config.EnableCommitAuthor)
	assert.Equal(t, "config", config.RepositoryName)
	assert.Equal(t, 0, len(config.RiskAcceptHashes))
	assert.Equal(t, 0, len(config.FalsePositiveHashes))
	assert.Equal(t, 0, len(config.Headers))
	assert.Equal(t, "", config.ContainerBindProjectPath)
	assert.Equal(t, true, config.IsEmptyRepositoryAuthorization())
	assert.Equal(t, 22, len(config.ToolsConfig))
	assert.Equal(t, false, config.DisableDocker)
	assert.Equal(t, "", config.CustomRulesPath)
	assert.Equal(t, false, config.EnableInformationSeverity)
	assert.Equal(t, 12, len(config.CustomImages))
	assert.Equal(t, 1, len(config.ShowVulnerabilitiesTypes))
	assert.Equal(t, false, config.EnableOwaspDependencyCheck)
	assert.Equal(t, false, config.EnableShellCheck)
}

func TestOverrideConfigFromConfigFile(t *testing.T) {
	wd, err := os.Getwd()
	require.Nil(t, err)

	defaultCfg := New()

	configFilePath := filepath.Join(wd, ".example-horusec-cli.json")
	defaultCfg.ConfigFilePath = configFilePath

	cfgMerged := defaultCfg.MergeFromConfigFile()

	assert.Equal(t, configFilePath, cfgMerged.ConfigFilePath)
	assert.Equal(t, "http://new-viper.horusec.com", cfgMerged.HorusecAPIUri)
	assert.Equal(t, int64(20), cfgMerged.TimeoutInSecondsRequest)
	assert.Equal(t, int64(100), cfgMerged.TimeoutInSecondsAnalysis)
	assert.Equal(t, int64(10), cfgMerged.MonitorRetryInSeconds)
	assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", cfgMerged.RepositoryAuthorization)
	assert.Equal(t, "json", cfgMerged.PrintOutputType)
	assert.Equal(t, "./output.json", cfgMerged.JSONOutputFilePath)
	assert.Equal(t, []string{"INFO"}, cfgMerged.SeveritiesToIgnore)
	assert.Equal(t, []string{"./assets"}, cfgMerged.FilesOrPathsToIgnore)
	assert.Equal(t, true, cfgMerged.ReturnErrorIfFoundVulnerability)
	assert.Equal(t, "./", cfgMerged.ProjectPath)
	assert.Equal(t, workdir.NewWorkDir(), cfgMerged.WorkDir)
	assert.Equal(t, true, cfgMerged.EnableGitHistoryAnalysis)
	assert.Equal(t, true, cfgMerged.CertInsecureSkipVerify)
	assert.Equal(t, "", cfgMerged.CertPath)
	assert.Equal(t, true, cfgMerged.EnableCommitAuthor)
	assert.Equal(t, "horus", cfgMerged.RepositoryName)
	assert.Equal(t, []string{"hash3", "hash4"}, cfgMerged.RiskAcceptHashes)
	assert.Equal(t, []string{"hash1", "hash2"}, cfgMerged.FalsePositiveHashes)
	assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, cfgMerged.Headers)
	assert.Equal(t, "test", cfgMerged.ContainerBindProjectPath)
	assert.Equal(t, true, cfgMerged.DisableDocker)
	assert.Equal(t, "test", cfgMerged.CustomRulesPath)
	assert.Equal(t, true, cfgMerged.EnableInformationSeverity)
	assert.Equal(t, true, cfgMerged.EnableOwaspDependencyCheck)
	assert.Equal(t, true, cfgMerged.EnableShellCheck)
	assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, cfgMerged.ShowVulnerabilitiesTypes)
	assert.Equal(t, toolsconfig.ToolConfig{
		IsToIgnore: true,
	}, cfgMerged.ToolsConfig[tools.GoSec])
	assert.Equal(t, "docker.io/company/go:latest", cfgMerged.CustomImages["go"])

}

func TestOverrideConfigFromEnvironmentVariables(t *testing.T) {
	authorization := uuid.New().String()
	wd, err := os.Getwd()
	require.Nil(t, err)

	configFilePath := filepath.Join(wd, ".example-horusec-cli.json")

	defaultCfg := New()
	require.Nil(t, err)
	defaultCfg.ConfigFilePath = configFilePath

	assert.NoError(t, os.Setenv(EnvHorusecAPIUri, "http://horusec.com"))
	assert.NoError(t, os.Setenv(EnvTimeoutInSecondsRequest, "99"))
	assert.NoError(t, os.Setenv(EnvTimeoutInSecondsAnalysis, "999"))
	assert.NoError(t, os.Setenv(EnvMonitorRetryInSeconds, "20"))
	assert.NoError(t, os.Setenv(EnvRepositoryAuthorization, authorization))
	assert.NoError(t, os.Setenv(EnvPrintOutputType, "sonarqube"))
	assert.NoError(t, os.Setenv(EnvJSONOutputFilePath, "./output-sonarqube.json"))
	assert.NoError(t, os.Setenv(EnvSeveritiesToIgnore, "INFO"))
	assert.NoError(t, os.Setenv(EnvFilesOrPathsToIgnore, "**/*_test.go, **/*_mock.go"))
	assert.NoError(t, os.Setenv(EnvReturnErrorIfFoundVulnerability, "false"))
	assert.NoError(t, os.Setenv(EnvProjectPath, "./horusec-manager"))
	assert.NoError(t, os.Setenv(EnvEnableGitHistoryAnalysis, "false"))
	assert.NoError(t, os.Setenv(EnvCertInsecureSkipVerify, "false"))
	assert.NoError(t, os.Setenv(EnvCertPath, "./"))
	assert.NoError(t, os.Setenv(EnvEnableCommitAuthor, "false"))
	assert.NoError(t, os.Setenv(EnvRepositoryName, "my-project"))
	assert.NoError(t, os.Setenv(EnvFalsePositiveHashes, "hash9, hash8"))
	assert.NoError(t, os.Setenv(EnvRiskAcceptHashes, "hash7, hash6"))
	assert.NoError(t, os.Setenv(EnvHeaders, "{\"x-auth\": \"987654321\"}"))
	assert.NoError(t, os.Setenv(EnvContainerBindProjectPath, "./my-path"))
	assert.NoError(t, os.Setenv(EnvDisableDocker, "true"))
	assert.NoError(t, os.Setenv(EnvEnableOwaspDependencyCheck, "true"))
	assert.NoError(t, os.Setenv(EnvEnableShellCheck, "true"))
	assert.NoError(t, os.Setenv(EnvCustomRulesPath, "test"))
	assert.NoError(t, os.Setenv(EnvEnableInformationSeverity, "true"))
	assert.NoError(t, os.Setenv(
		EnvShowVulnerabilitiesTypes, fmt.Sprintf(
			"%s, %s", vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString(),
		),
	))
	assert.NoError(t, os.Setenv(EnvLogFilePath, "test"))

	configs := defaultCfg.MergeFromEnvironmentVariables()

	assert.Equal(t, configFilePath, configs.ConfigFilePath)
	assert.Equal(t, "http://horusec.com", configs.HorusecAPIUri)
	assert.Equal(t, int64(99), configs.TimeoutInSecondsRequest)
	assert.Equal(t, int64(999), configs.TimeoutInSecondsAnalysis)
	assert.Equal(t, int64(20), configs.MonitorRetryInSeconds)
	assert.Equal(t, authorization, configs.RepositoryAuthorization)
	assert.Equal(t, "sonarqube", configs.PrintOutputType)
	assert.Equal(t, "./output-sonarqube.json", configs.JSONOutputFilePath)
	assert.Equal(t, []string{"INFO"}, configs.SeveritiesToIgnore)
	assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.FilesOrPathsToIgnore)
	assert.Equal(t, false, configs.ReturnErrorIfFoundVulnerability)
	assert.Equal(t, "./horusec-manager", configs.ProjectPath)
	assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
	assert.Equal(t, false, configs.EnableGitHistoryAnalysis)
	assert.Equal(t, false, configs.CertInsecureSkipVerify)
	assert.Equal(t, "./", configs.CertPath)
	assert.Equal(t, false, configs.EnableCommitAuthor)
	assert.Equal(t, "my-project", configs.RepositoryName)
	assert.Equal(t, []string{"hash7", "hash6"}, configs.RiskAcceptHashes)
	assert.Equal(t, []string{"hash9", "hash8"}, configs.FalsePositiveHashes)
	assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.Headers)
	assert.Equal(t, "./my-path", configs.ContainerBindProjectPath)
	assert.Equal(t, true, configs.DisableDocker)
	assert.Equal(t, "test", configs.CustomRulesPath)
	assert.Equal(t, true, configs.EnableInformationSeverity)
	assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
	assert.Equal(t, true, configs.EnableShellCheck)
	assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString()}, configs.ShowVulnerabilitiesTypes)
}
