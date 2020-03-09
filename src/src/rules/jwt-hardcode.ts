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

// Check if it is:
// const {JWK} = require('jose')
// ...
// JWK.asKey(...)
function isJwkAsKey(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  return (packageName === 'jose' && name === 'JWK');
}

// Check for JWK.asKey(...) with literal argumen
function isHardcodedJwkKey(arg: estree.Node, ty: stadt.Type): boolean {
  if (arg.type === 'CallExpression' && arg.callee.type === 'MemberExpression') {
    const objType = getType(arg.callee.object);
    if (objType && objType.mustSatisfy(isJwkAsKey) && arg.callee.property.type === 'Identifier' && arg.callee.property.name === 'asKey') {
      const keyType = arg.arguments[0] && getType(arg.arguments[0]);
      if (keyType) {
        return keyType.mustSatisfy(t => t.isLiteral());
      }
    }
  }
  return false;
}

function isHardocdedSecret(arg: estree.Node, ty: stadt.Type): boolean {
  return ty.mustSatisfy(t => t.isLiteral() || isHardcodedJwkKey(arg, ty));
}

function findHardcodedSecret(node: estree.CallExpression) {
  if (node.callee.type === 'MemberExpression') {
    const obj: estree.MemberExpression = (node.callee as estree.MemberExpression);
    const ty: stadt.Type | undefined = getType(obj.object);

    if (ty && possibleTypes(ty).some(isJwtLibrary)) {
      if (obj.property && ['sign', 'verify'].includes((obj.property as estree.Identifier).name)) {
        const secret = node.arguments[1];
        const secretType = secret && getType(secret);
        if (secretType && isHardocdedSecret(secret, secretType)) {
          return secret;
        }
      }
    }
  }
}

export const rule: Rule = {
  create(context: Context) {
    return {
      CallExpression(node: estree.CallExpression) {
        const secret = findHardcodedSecret(node);
        if (secret) {
          context.report({
            node: secret,
            checkId: 'jwt-hardcoded-secret',
            extra: {}
          });
        }
      }
    }
  }
}