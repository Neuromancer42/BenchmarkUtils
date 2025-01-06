/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Sascha Knoop
 * @created 2024
 */
package org.owasp.benchmarkutils.score.parsers.csv;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.*;
import org.owasp.benchmarkutils.score.parsers.Reader;

/**
 * Reader for <a
 * href="https://www.synopsys.com/software-integrity/security-testing/dast.html">WhiteHat Dynamic
 * (DAST)</a> results.
 */
public class LLMReportSimpleReader extends Reader {

    private final Map<String, Integer> categoryMappings = new HashMap<>();

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv") && resultFile.filename().contains("LLM_");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        String prefix = "Benchmark_1.2_LLM_";
        String filename = resultFile.filename();
        String modelname =
                filename.substring(
                        filename.lastIndexOf(prefix) + prefix.length(),
                        resultFile.filename().lastIndexOf(".csv"));
        TestSuiteResults tr =
                new TestSuiteResults("LLM - " + modelname, false, TestSuiteResults.ToolType.Hybrid);

        try (CSVParser records = resultFile.csvRecords()) {
            records.stream().forEach(r -> tr.put(toTestCaseResult(r)));
        }

        return tr;
    }

    private TestCaseResult toTestCaseResult(CSVRecord record) {
        int benchId = Integer.parseInt(record.get(0));
        String cweName = record.get(1);
        int cweId = Integer.parseInt(record.get(2));

        TestCaseResult tcr = new TestCaseResult();

        tcr.setCategory(cweName);
        tcr.setCWE(cweId);
        tcr.setNumber(benchId);

        return tcr;
    }

    private int cweLookup(String category) {
        if (categoryMappings.containsKey(category)) {
            return categoryMappings.get(category);
        }

        System.out.println("WARNING: LLM result file contained unmapped category: " + category);
        return CweNumber.DONTCARE;
    }
}
