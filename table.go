package main

import (
	"github.com/fatih/color"
	"github.com/rodaine/table"
)

func CreateTable(targets []string) {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	colmnFmt := color.New(color.FgYellow).SprintfFunc()

	t := table.New("Ping", "IPv4 Address", "MAC Address", "Hostname", "Vendor")
	t.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(colmnFmt)

	t.AddRow("1", "192.16.12.1", "00:00:00:00:00:00", "Router", "Cisco")
	t.AddRow("2", targets[0], "00:00:00:00:00:00", "Host", "Unknown")

	t.Print()
}
