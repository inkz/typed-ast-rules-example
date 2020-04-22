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

// Check if it is `jsonwebtoken` or `jose` module
function isJwtLibrary(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  return (packageName === '@types/jsonwebtoken' && (name.indexOf('jsonwebtoken') > -1))
    || (packageName === 'jose' && name === 'JWT');
}

function isOrmDocument(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  return packageName === '@types/mongoose' && name === 'Document';
}

function findOrmExposure(node: estree.CallExpression) {
  if (node.callee.type === 'MemberExpression') {
    const obj: estree.MemberExpression = (node.callee as estree.MemberExpression);
    const ty: stadt.Type | undefined = getType(obj.object);

    if (ty && possibleTypes(ty).some(isJwtLibrary)) {
      if (obj.property && (obj.property as estree.Identifier).name === 'sign') {
        const payload = node.arguments[0];
        const payloadType = payload && getType(payload);
        if (payloadType && possibleTypes(payloadType).some(isOrmDocument)) {
          return payload;
        }
      }
    }
  }
}

export const rule: Rule = {
  create(context: Context) {
    return {
      CallExpression(node: estree.CallExpression) {
        const result = findOrmExposure(node);
        if (result) {
          context.report({
            node: result,
            checkId: 'orm-expose',
            extra: {}
          });
        }
      }
    };
  }
};