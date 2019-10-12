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

function findSecret(arg: estree.Node, context: Context): void {
  const secretType = getType(arg);
  if (secretType && secretType.isString()) {
    context.report({
      node: arg,
      checkId: 'jwt-secret',
      extra: {
        secret: (secretType as stadt.LiteralType).value
      }
    });
  }
}

export const rule: Rule = {
  create(context: Context) {
    return {
      CallExpression(node: estree.CallExpression) {
        if (node.callee && (node.callee as estree.MemberExpression).object) {
          const obj: estree.MemberExpression = (node.callee as estree.MemberExpression);
          const ty: stadt.Type | undefined = getType(obj.object);
          if (ty && possibleTypes(ty).some(isJWT)) {
            if (obj.property && (obj.property as estree.Identifier).name === 'decode') {
              context.report({
                node,
                checkId: 'jwt-decode'
              });           
            }
            if (obj.property && (obj.property as estree.Identifier).name === 'verify') {
              const [, secret, opts] = node.arguments;
              secret && findSecret(secret, context);
              if (opts) {
                const optsType = getType(opts);
                if (optsType && optsType.isPrimitive()) {
                  context.report({
                    node,
                    checkId: 'jwt-opts-primitive'
                  });
                }
              }
            }
            if (obj.property && (obj.property as estree.Identifier).name === 'sign') {
              const ty: stadt.Type | undefined = getType(obj.object);
              const [payload, secret, ] = node.arguments;
              secret && findSecret(secret, context);
              const argType = getType(payload);
              if (argType && argType.isObject()) {
                const keysMap = argType.properties.keys();
                const keys = [];
                for (let key of keysMap) {
                  keys.push(key);
                }
                context.report({
                  node,
                  checkId: 'jwt-payload-key',
                  extra: {
                    keys
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
