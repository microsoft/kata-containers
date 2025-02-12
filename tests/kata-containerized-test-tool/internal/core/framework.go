package core

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "time"
)

type Framework struct {
    tests     []Test
    outputDir string
}

func NewFramework(outputDir string) *Framework {
    return &Framework{
        outputDir: outputDir,
    }
}

func (f *Framework) AddTest(test Test) {
    f.tests = append(f.tests, test)
}

func (f *Framework) RunAll(ctx context.Context) error {
    results := make([]TestResult, 0)
    
    for _, test := range f.tests {
        result := test.Run(ctx)
        results = append(results, result)
    }
    
    return f.saveResults(results)
}

func (f *Framework) saveResults(results []TestResult) error {
    filename := fmt.Sprintf("%s/results_%s.json", 
        f.outputDir, 
        time.Now().Format("20060102_150405"))
    
    data, err := json.MarshalIndent(results, "", "    ")
    if err != nil {
        return err
    }
    
    return os.WriteFile(filename, data, 0644)
}