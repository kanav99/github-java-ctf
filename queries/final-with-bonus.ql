/** 
* @kind path-problem 
*/
import java
import semmle.code.java.dataflow.TaintTracking
// import DataFlow::PartialPathGraph
import DataFlow::PathGraph
import semmle.code.java.dataflow.FlowSources

class TypeConstraintValidator extends GenericInterface {
  TypeConstraintValidator() { hasQualifiedName("javax.validation", "ConstraintValidator") }
}

class CustomStepper extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess callToGetter, GetterMethod getterMethod |
        succ.asExpr() = callToGetter and
        pred.asExpr() = callToGetter.getQualifier() and
        callToGetter.getCallee() = getterMethod
    ) or
    exists(MethodAccess callToMethod |
        succ.asExpr() = callToMethod and
        pred.asExpr() = callToMethod.getQualifier() and
        (callToMethod.getMethod().getName() in ["keySet", "stream", "map", "collect"] )
    ) or
    exists(ConstructorCall callToConstructor |
        succ.asExpr() = callToConstructor and
        callToConstructor.getArgument(0) = pred.asExpr() and
        callToConstructor.getConstructedType().getErasure().(Class).hasQualifiedName("java.util", "HashSet")
    )
  }
}

class TryCatchStepper extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(TryStmt t, CatchClause c, MethodAccess ma, MethodAccess ma2 |
      // connect try and catch
      c.getTry() = t and
      // in catch, the method access would be the successor...
      ma2 = succ.asExpr() and
      // restricting to those methods that write something
      (
        ma2.getMethod().getName() in [
          "getMessage", "getStackTrace",
          "getSuppressed", "toString",
          "getLocalizedMessage" ] or
        ma2.getMethod().getName().prefix(3) = "get" or
        ma2.getMethod() instanceof GetterMethod
      ) and
      // and it's qualifier should be the error variable.
      c.getVariable().getAnAccess() = ma2.getQualifier() and
      // predecessor would be an argument of a method access...
      ma.getAnArgument() = pred.asExpr() and
      // which is contained in the try statement
      ma.getEnclosingStmt().getParent*() = t.getBlock() and
      // and the method should throw some subtype of the caught clause type
      ma.getMethod().getAThrownExceptionType().getASupertype*() = c.getACaughtType() and
      // coz obviously...
      not pred.asExpr() instanceof Literal
    )
  }
}

class MyTaintTrackingConfig extends TaintTracking::Configuration {
    MyTaintTrackingConfig() { this = "MyTaintTrackingConfig" }

    override predicate isSource(DataFlow::Node source) { 
        exists(Method isValid, ParameterizedInterface originalConstrainValidator, RemoteFlowSource r |
            source.asParameter() = isValid.getParameter(0) and
            isValid.hasName("isValid") and 
            isValid.getDeclaringType().hasSupertype(originalConstrainValidator) and
            originalConstrainValidator.getSourceDeclaration() instanceof TypeConstraintValidator and
            isValid.getAnAnnotation() instanceof OverrideAnnotation and
            (
              exists(ValidatedClass c |
                c.hasValidator(isValid) and (
                  r.asParameter().getType().getName() = c.getName() or
                  r.asParameter().getType().(Class).getAField().getType().getName() = c.getName() or
                  r.asParameter().getType().(Class).getAField().getType().(Class).getAField().getType().getName() = c.getName()
                )
              )
              or
              exists(ValidatedField f, Class c1, Class c2, Class c3 |
                f.hasValidator(isValid) and (
                  r.asParameter().getType().getName() = c1.getName() and
                  c1.getAField().getType().getName() = c2.getName() and
                  c2.getAField().getType().getName() = c3.getName() and
                  (
                    c1.getAField() = f or
                    c2.getAField() = f or
                    c3.getAField() = f
                  )
                )
              )
            )
        )
    }

    override predicate isSink(DataFlow::Node sink) { 
        exists(MethodAccess c | sink.asExpr() = c.getArgument(0) and
            c.getMethod().hasName("buildConstraintViolationWithTemplate"))
    }
}

class ValidatedField extends Field {
  ValidatedField() {
    exists(Annotation constraintAnnotation, 
           Annotation descriptionAnnotation,
           Class validatorClass, Method m | 
        descriptionAnnotation = constraintAnnotation.getType().getAnAnnotation() and
        descriptionAnnotation.getType().hasQualifiedName("javax.validation", "Constraint") and
        descriptionAnnotation.getValue("validatedBy").(ArrayInit).getAnInit().(TypeLiteral).getTypeName().getType() = validatorClass and
        m.getDeclaringType() = validatorClass and
        m.getName() = "isValid" and
        this = constraintAnnotation.getAnnotatedElement()
    )
  }

  predicate hasValidator(Method m) {
    exists(Annotation constraintAnnotation, 
           Annotation descriptionAnnotation, 
           Class validatorClass | 
        descriptionAnnotation = constraintAnnotation.getType().getAnAnnotation() and
        descriptionAnnotation.getType().hasQualifiedName("javax.validation", "Constraint") and
        descriptionAnnotation.getValue("validatedBy").(ArrayInit).getAnInit().(TypeLiteral).getTypeName().getType() = validatorClass and
        m.getDeclaringType() = validatorClass and
        this = constraintAnnotation.getAnnotatedElement()
    )
  }
}

class ValidatedClass extends Class {
  ValidatedClass() {
    exists(Annotation constraintAnnotation, 
           Annotation descriptionAnnotation,
           Class validatorClass, Method m | 
        descriptionAnnotation = constraintAnnotation.getType().getAnAnnotation() and
        descriptionAnnotation.getType().hasQualifiedName("javax.validation", "Constraint") and
        descriptionAnnotation.getValue("validatedBy").(ArrayInit).getAnInit().(TypeLiteral).getTypeName().getType() = validatorClass and
        m.getDeclaringType() = validatorClass and
        m.getName() = "isValid" and
        this = constraintAnnotation.getAnnotatedElement().(Class).getErasure()
    )
  }

  predicate hasValidator(Method m) {
    exists(Annotation constraintAnnotation, 
           Annotation descriptionAnnotation, 
           Class validatorClass | 
        descriptionAnnotation = constraintAnnotation.getType().getAnAnnotation() and
        descriptionAnnotation.getType().hasQualifiedName("javax.validation", "Constraint") and
        descriptionAnnotation.getValue("validatedBy").(ArrayInit).getAnInit().(TypeLiteral).getTypeName().getType() = validatorClass and
        m.getDeclaringType() = validatorClass and
        this = constraintAnnotation.getAnnotatedElement().(Class).getErasure()
    )
  }
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
