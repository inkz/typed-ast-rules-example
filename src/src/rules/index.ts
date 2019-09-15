import * as estree from "estree";
import * as walker from "estree-walker";
// import * as requireRequest from "./require-request";
import * as jwtPayloadKeys from "./jwt-payload-keys";
import * as stadt from "stadt";

// The API design here is intentionally patterned after a simplified version of
// eslint's.

export type Report = {
  node: estree.Node;
  checkId: string;
  extra?: object;
};

// A Context is the mechanism for rules to output their reports. Eventually
// it'll also contain information about the source tree, etc.
export class Context {
  private reports: Report[] = [];
  // A rule should call this when it has some kind of finding.
  public report(report: Report) {
    this.reports.push(report);
  }
  public getReports(): ReadonlyArray<Report> {
    return this.reports;
  }
}

// Each property corresponds to a possible value for a node's `type` field. The
// corresponding method is called upon entering the subtree rooted at that node
// (i.e., before any children).
export interface Visitor {
  CallExpression?: (node: estree.CallExpression) => void;
  JSXIdentifier?: (node: estree.Node) => void;
  Literal?: (node: estree.Literal) => void;
  MemberExpression?: (node: estree.MemberExpression) => void;
  ImportDeclaration?: (node: estree.ImportDeclaration) => void;
  AssignmentExpression?: (node: estree.AssignmentExpression) => void;
  NewExpression?: (node: estree.NewExpression) => void;
  VariableDeclarator?: (node: estree.VariableDeclarator) => void;
}

export interface Rule {
  create: (context: Context) => Visitor;
}

// Hack to deal with the fact that the estree node type definition doesn't have
// an inferredType property.
export function getType(node: estree.Node): stadt.Type | undefined {
  return stadt.fromJSON((node as any).inferredType);
}

// If ty is a union type, returns the array of possible values (recursively).
// Otherwise, returns `[ty]`.
export function possibleTypes(ty: stadt.Type): stadt.Type[] {
  if (ty.isUnion()) {
    let types: stadt.Type[] = [];
    for (const inner of ty.types) {
      types = types.concat(possibleTypes(inner));
    }
    return types;
  } else {
    return [ty];
  }
}

export const all: ReadonlyArray<Rule> = [
  // requireRequest.rule,
  jwtPayloadKeys.rule
];

// Constructs a context for the given AST, runs the given rules over it, and
// returns the context.
export function runRules(
  ast: walker.Node,
  rules: ReadonlyArray<Rule>
): Context {
  const context = new Context();
  const visitors = rules.map(rule => rule.create(context));
  walker.walk(ast, {
    enter(node) {
      for (const visitor of visitors) {
        if (visitor[node.type]) {
          visitor[node.type](node);
        }
      }
    }
  });
  return context;
}
