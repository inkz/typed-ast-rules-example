import * as estree from 'estree';
import * as stadt from 'stadt';
import { Context, Rule, getType, possibleTypes } from './index';

function isJwtLibrary(ty: stadt.Type): boolean {
  if (!(ty instanceof stadt.NominativeType)) {
    return false;
  }
  const { name, packageName } = ty.fullyQualifiedName;
  //check if it is `jsonwebtoken` or `jose ` module
  return (packageName === '@types/jsonwebtoken' && (name.indexOf('jsonwebtoken') > -1))
    || (packageName === 'jose' && ['JWT', 'JWK'].includes(name));
}

function findHardcodedSecret(node: estree.CallExpression) {
  if (node.callee.type === 'MemberExpression') {
    const obj: estree.MemberExpression = (node.callee as estree.MemberExpression);
    const ty: stadt.Type | undefined = getType(obj.object);

    if (ty && possibleTypes(ty).some(isJwtLibrary)) {
      let secret;
      if (obj.property && (obj.property as estree.Identifier).name === 'sign') {
        secret = node.arguments[1];
      }
      if (obj.property && (obj.property as estree.Identifier).name === 'asKey') {
        secret = node.arguments[0];
      }
      if (secret) {
        const secretType = getType(secret);
        if (secretType && secretType.mustSatisfy(t => t.isLiteral())) {
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