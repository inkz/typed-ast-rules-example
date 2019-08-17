import * as estree from "estree";
import * as stadt from "stadt";
import { Context, Rule, getType, possibleTypes } from "./index";

function isRequire(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  return (
    packageName === "@types/node" &&
    (name == "NodeRequire" || name == "NodeRequireFunction")
  );
}

function isRequest(object: any): boolean {
  if (object && object.type === 'MemberExpression' && object.object) {
    const ty: stadt.Type = stadt.fromJSON(object.object.inferredType);
    if (ty) {
      if (!(ty instanceof stadt.NominativeType)) {
        return false;
      }
      const { name, packageName } = ty.fullyQualifiedName;
      return (packageName === "@types/express-serve-static-core" && name === "Request");
    }
  }
  return false;
}

function getIdentifiers(arg: any): estree.Identifier[] {
  const types = [];
  if (Array.isArray(arg)) {
    arg.forEach(a => types.push(...getIdentifiers(a)));
  } else if (arg.type === 'Identifier') {
    types.push(arg);
  } else {
    if ((arg as any).left) {
      types.push(...getIdentifiers(arg.left));
    }
    if ((arg as any).right) {
      types.push(...getIdentifiers(arg.right));
    }
    if ((arg as any).arguments) {
      types.push(...getIdentifiers(arg.arguments));
    }
    if ((arg as any).expressions) {
      types.push(...getIdentifiers(arg.expressions));
    }
  }
  return types;
}

export const rule: Rule = {
  create(context: Context) {
    const reqVariables: String[] = [];
    return {
      VariableDeclarator(node: estree.VariableDeclarator) {
        if (isRequest(node.init && (node.init as any).object)) {
          const id: estree.Pattern = node.id;
          if (id.type === 'Identifier') {
            const name = (id as estree.Identifier).name;
            reqVariables.push(name);
          }
        }
      },
      CallExpression(node: estree.CallExpression) {
        const ty = getType(node.callee);
        if (!(ty && possibleTypes(ty).some(isRequire))) {
          return;
        }
        const args = node.arguments;
        if (args.length == 0) {
          // An empty require is invalid, but not insecure.
          return;
        }
        const argType = getType(args[0]);
        const object = (args[0] as any).object;
        const isSafe =
          argType &&
          possibleTypes(argType).every(t => t instanceof stadt.LiteralType);
        if (!isSafe) {
          if (isRequest(object)) {
            context.report({
              node,
              checkId: "require-from-request"
            });
          } else {
            const identifiers = getIdentifiers(args[0]);
            identifiers.forEach((id: estree.Identifier) => {
              const name = id.name;
              if (reqVariables.includes(name)) {
                context.report({
                  node,
                  checkId: "require-request-var"
                });
              }
            });
          }
        }
      }
    };
  }
};