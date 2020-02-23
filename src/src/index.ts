import * as assert from "assert";
import * as estree from "estree";
import * as fs from "fs";
import * as glob from "glob";
import * as path from "path";
import * as rules from "./rules";
import * as walker from "estree-walker";

type Point = {
  line: number;
  col?: number;
};

type Result = {
  check_id: string;
  path: string;
  start?: Point;
  end?: Point;
  extra?: any;
};

function positionToPoint(position: estree.Position): Point {
  return {
    line: position.line,
    col: position.column
  };
}

// Convert from our format to the standard analyzer output format.
function reportToResult(report: rules.Report, path: string): Result {
  const result: Result = {
    check_id: report.checkId,
    path
  };
  if (report.extra) {
    result.extra = report.extra;
  }
  const loc = report.node.loc;
  if (!loc) {
    return result;
  }
  if (loc.start) {
    result.start = positionToPoint(loc.start);
  }
  if (loc.end) {
    result.end = positionToPoint(loc.end);
  }
  return result;
}

async function main() {
  const inputDir = process.argv[2];
  assert(inputDir, "must supply directory of ASTs as input directory");
  const astPaths = glob.sync("**/*.ast.json", {
    cwd: inputDir,
    dot: true,
    absolute: true
  });
  const results = [];
  const filteredAstPaths = astPaths.filter((astPath) => {
    const parts = astPath.split(path.sep);
    if (
      parts.includes('test')
      || parts.includes('tests')
      || astPath.endsWith('.spec.js.ast.json')
      || astPath.endsWith('.test.js.ast.json')
    ) {
      return false;
    }
    return true;
  });
  for (const astPath of filteredAstPaths) {
    const ast = JSON.parse(await fs.promises.readFile(astPath, "utf8"));
    for (const report of rules.runRules(ast, rules.all).getReports()) {
      let originalPath = path.relative(inputDir, astPath);
      originalPath = originalPath.substring(
        0,
        originalPath.lastIndexOf(".ast.json")
      );
      results.push(reportToResult(report, originalPath));
    }
  }
  process.stdout.write(
    JSON.stringify(
      {
        results
      },
      null,
      2
    )
  );
}

if (require.main == module) {
  main().catch(err => {
    console.error("Failure", err);
    process.exit(1);
  });
}
