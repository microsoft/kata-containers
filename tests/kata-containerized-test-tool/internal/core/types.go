package core

import (
	"context"
	"encoding/xml"
	"time"
)

type TestResult struct {
	Name           string
	StartTime      time.Time
	EndTime        time.Time
	Success        bool
	Metrics        map[string]interface{}
	ExpectedValues map[string]interface{}
	Error          string
}

type Test interface {
	Name() string
	Run(ctx context.Context, expectedValues map[string]interface{}) TestResult
}

type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Time      float64         `xml:"time,attr"`
	Name      string          `xml:"name,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	Name       string          `xml:"name,attr"`
	ClassName  string          `xml:"classname,attr"`
	Time       float64         `xml:"time,attr"`
	Failure    *JUnitFailure   `xml:"failure,omitempty"`
	Properties JUnitProperties `xml:"properties,omitempty"`
}

type JUnitProperties struct {
	Properties []JUnitProperty `xml:"property"`
}

type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Value   string `xml:",chardata"`
}
