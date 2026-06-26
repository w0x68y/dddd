package parsers

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
)

type workflowLoader struct {
	pathFilter *filter.PathFilter
	tagFilter  *filter.TagFilter
	options    *protocols.ExecutorOptions
}

// NewLoader returns a new workflow loader structure
func NewLoader(options *protocols.ExecutorOptions) (model.WorkflowLoader, error) {
	tagFilter, err := filter.New(&filter.Config{
		Authors:           options.Options.Authors,
		Tags:              options.Options.Tags,
		ExcludeTags:       options.Options.ExcludeTags,
		IncludeTags:       options.Options.IncludeTags,
		IncludeIds:        options.Options.IncludeIds,
		ExcludeIds:        options.Options.ExcludeIds,
		Severities:        options.Options.Severities,
		ExcludeSeverities: options.Options.ExcludeSeverities,
		Protocols:         options.Options.Protocols,
		ExcludeProtocols:  options.Options.ExcludeProtocols,
		IncludeConditions: options.Options.IncludeConditions,
	})
	if err != nil {
		return nil, err
	}
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: options.Options.IncludeTemplates,
		ExcludedTemplates: options.Options.ExcludedTemplates,
	}, options.Catalog)

	return &workflowLoader{pathFilter: pathFilter, tagFilter: tagFilter, options: options}, nil
}

func (w *workflowLoader) GetTemplatePathsByTags(templateTags []string) []string {
	includedTemplates, errs := w.options.Catalog.GetTemplatesPath([]string{config.DefaultConfig.TemplatesDirectory})
	for template, err := range errs {
		gologger.Error().Msgf("Could not find template '%s': %s", template, err)
	}

	templatePathMap := w.pathFilter.Match(includedTemplates)

	loadedTemplates := make([]string, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, _ := LoadTemplate(templatePath, w.tagFilter, templateTags, w.options.Catalog)
		if loaded {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	return loadedTemplates
}

func (w *workflowLoader) GetTemplatePaths(templatesList []string, noValidate bool) []string {
	includedTemplates, errs := w.options.Catalog.GetTemplatesPath(templatesList)
	embeddedTemplates, embeddedMatches := w.getEmbeddedTemplatePaths(templatesList)
	for template, err := range errs {
		if embeddedPath, ok := embeddedMatches[template]; ok {
			if w.options.Options.PocDebug {
				gologger.Info().Msgf("[POC-DEBUG] workflow template=%s resolved from embedded path=%s", template, embeddedPath)
			}
			continue
		}
		gologger.Error().Msgf("Could not find template '%s': %s", template, err)
	}
	includedTemplates = append(includedTemplates, embeddedTemplates...)
	templatesPathMap := w.pathFilter.Match(includedTemplates)
	embeddedPathMap := make(map[string]struct{}, len(embeddedTemplates))
	for _, templatePath := range embeddedTemplates {
		embeddedPathMap[templatePath] = struct{}{}
	}

	loadedTemplates := make([]string, 0, len(templatesPathMap))
	for templatePath := range templatesPathMap {
		if _, ok := embeddedPathMap[templatePath]; ok {
			loadedTemplates = append(loadedTemplates, templatePath)
			continue
		}
		matched, err := LoadTemplate(templatePath, w.tagFilter, nil, w.options.Catalog)
		if err != nil && !matched {
			gologger.Warning().Msg(err.Error())
		} else if matched || noValidate {
			loadedTemplates = append(loadedTemplates, templatePath)
		}
	}
	sort.Strings(loadedTemplates)
	if w.options.Options.PocDebug {
		gologger.Info().Msgf("[POC-DEBUG] workflow requested=%s resolved=%d", strings.Join(templatesList, ","), len(loadedTemplates))
	}
	return loadedTemplates
}

func (w *workflowLoader) getEmbeddedTemplatePaths(templatesList []string) ([]string, map[string]string) {
	matches := make(map[string]string)
	seen := make(map[string]struct{})
	paths := make([]string, 0, len(templatesList))

	for _, template := range templatesList {
		for _, candidate := range embeddedTemplateCandidates(template) {
			file, err := w.options.EmbedPocs.Open(candidate)
			if err != nil {
				continue
			}
			_ = file.Close()
			matches[template] = candidate
			if _, ok := seen[candidate]; !ok {
				seen[candidate] = struct{}{}
				paths = append(paths, candidate)
			}
			break
		}
	}
	sort.Strings(paths)
	return paths, matches
}

func embeddedTemplateCandidates(template string) []string {
	normalized := filepath.ToSlash(strings.TrimSpace(template))
	normalized = strings.TrimPrefix(normalized, "./")
	normalized = strings.TrimPrefix(normalized, "/")
	if normalized == "" {
		return nil
	}

	trimmedConfig := strings.TrimPrefix(normalized, "config/pocs/")
	trimmedOfficial := strings.TrimPrefix(trimmedConfig, "nuclei-templates/")
	candidates := []string{
		"config/pocs/nuclei-templates/" + trimmedOfficial,
		"config/pocs/" + trimmedConfig,
		normalized,
	}

	seen := make(map[string]struct{}, len(candidates))
	deduped := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		deduped = append(deduped, candidate)
	}
	return deduped
}
