import * as estree from 'estree';
import * as stadt from 'stadt';
import { Context, Rule, getType, possibleTypes } from './index';

// Check if it is `jsonwebtoken` or `jose` module
function isJwtLibrary(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  return (packageName === '@types/jsonwebtoken' && (name.indexOf('jsonwebtoken') > -1))
    || (packageName === 'jose' && name === 'JWT');
}

function findJWTPayloadType(node: estree.CallExpression) {
  if (node.callee.type === 'MemberExpression') {
    const obj: estree.MemberExpression = (node.callee as estree.MemberExpression);
    const ty: stadt.Type | undefined = getType(obj.object);

    if (ty && possibleTypes(ty).some(isJwtLibrary)) {
      if (obj.property && (obj.property as estree.Identifier).name === 'sign') {
        const payload = node.arguments[0];
        const payloadType = payload && getType(payload);
        return payloadType;
      }
    }
  }
}

export const rule: Rule = {
  create(context: Context) {
    return {
      CallExpression(node: estree.CallExpression) {
        const ty = findJWTPayloadType(node);
        if (ty) {
          context.report({
            node: node,
            checkId: 'jwt-expo',
            extra: {
              type: ty
            }
          });
        }
      }
    }
  }
}