import * as estree from 'estree';
import * as stadt from 'stadt';
import { Context, Rule, getType, possibleTypes } from './index';

function isJWT(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  return (packageName === '@types/jsonwebtoken' && (name.indexOf('jsonwebtoken') > -1))
    || (packageName === '@panva/jose' && ['JWT', 'JWS'].includes(name));
}

export const rule: Rule = {
  create(context: Context) {
    return {
      CallExpression(node: estree.CallExpression) {
        if (node.callee && (node.callee as estree.MemberExpression).object) {
          const obj: estree.MemberExpression = (node.callee as estree.MemberExpression);
          if (obj.property && (obj.property as estree.Identifier).name === 'sign') {
            const ty: stadt.Type | undefined = getType(obj.object);
            if (ty && possibleTypes(ty).some(isJWT)) {
              const arg = node.arguments[0];
              const argType = getType(arg);
              if (argType && argType.isObject()) {
                const keys = argType.properties.keys();
                for (let key of keys) {
                  context.report({
                    node,
                    checkId: 'jwt-payload-key',
                    extra: {
                      key
                    }
                  });
                }
              }
            }
          }
        }
      }
    }
  }
}
