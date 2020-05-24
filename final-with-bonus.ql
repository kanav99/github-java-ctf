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
    exists(MethodAccess ma, GetterMethod m |
        succ.asExpr() = ma and
        pred.asExpr() = ma.getQualifier() and
        ma.getCallee() = m
    ) or
    exists(MethodAccess ma |
        succ.asExpr() = ma and
        pred.asExpr() = ma.getQualifier() and
        (ma.getMethod().getName() in ["keySet", "stream", "map", "collect"] )
    ) or
    exists(ConstructorCall ma |
        succ.asExpr() = ma and
        ma.getArgument(0) = pred.asExpr() and
        ma.getConstructedType().getName() = "HashSet<String>"
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
        exists(Method m, ParameterizedInterface p |
            source.asParameter() = m.getParameter(0) and
            m.getName() = "isValid" and 
            m.getDeclaringType().hasSupertype(p) and
            p.getSourceDeclaration() instanceof TypeConstraintValidator and
            m.getAnAnnotation() instanceof OverrideAnnotation and
            (
              exists(RemoteFlowSource r, ValidatedClass c |
                c.hasValidator(m) and (
                  r.asParameter().getType().getName() = c.getName() or
                  r.asParameter().getType().(Class).getAField().getType().getName() = c.getName() or
                  r.asParameter().getType().(Class).getAField().getType().(Class).getAField().getType().getName() = c.getName()
                )
              )
              or
              exists(RemoteFlowSource r, ValidatedField f, Class c1, Class c2, Class c3 |
                f.hasValidator(m) and (
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
            string validatorClassName, 
            Class validatorClass, 
            Method m | 
      // connect validatorClassName and validatorClass as they should
      validatorClass.hasName(validatorClassName) and
      // Check if the particular annotation's type has a `@Constraint` annotation
      constraintAnnotation.getType().getAnAnnotation().getType().hasQualifiedName("javax.validation", "Constraint") and
      // Get the value of the "validatedBy" in the `@Constraint` annotation and map it's class to validatorClass
      constraintAnnotation.getType().getAnAnnotation().getValue("validatedBy").(ArrayInit).getAnInit().getType().getName() = "Class<" + validatorClassName + ">" and
      // isValid method should be declared inside the validatorClass
      m.getDeclaringType() = validatorClass and
      // and it should have a name "isValid"
      m.getName() = "isValid" and
      // should be in the source
      m.fromSource() and
      this = constraintAnnotation.getAnnotatedElement()
    )
  }

  predicate hasValidator(Method m) {
    exists(Annotation constraintAnnotation, 
            string validatorClassName, 
            Class validatorClass | 
      // connect validatorClassName and validatorClass as they should
      validatorClass.hasName(validatorClassName) and
      // Check if the particular annotation's type has a `@Constraint` annotation
      constraintAnnotation.getType().getAnAnnotation().getType().hasQualifiedName("javax.validation", "Constraint") and
      // Get the value of the "validatedBy" in the `@Constraint` annotation and map it's class to validatorClass
      constraintAnnotation.getType().getAnAnnotation().getValue("validatedBy").(ArrayInit).getAnInit().getType().getName() = "Class<" + validatorClassName + ">" and
      // isValid method should be declared inside the validatorClass
      m.getDeclaringType() = validatorClass and
      // and it should have a name "isValid"
      m.getName() = "isValid" and
      // should be in the source
      m.fromSource() and
      this = constraintAnnotation.getAnnotatedElement()
    )
  }
}

class ValidatedClass extends Class {
  ValidatedClass() {
    exists(Annotation constraintAnnotation, 
            string validatorClassName, 
            Class validatorClass, 
            Method m | 
      // connect validatorClassName and validatorClass as they should
      validatorClass.hasName(validatorClassName) and
      // Check if the particular annotation's type has a `@Constraint` annotation
      constraintAnnotation.getType().getAnAnnotation().getType().hasQualifiedName("javax.validation", "Constraint") and
      // Get the value of the "validatedBy" in the `@Constraint` annotation and map it's class to validatorClass
      constraintAnnotation.getType().getAnAnnotation().getValue("validatedBy").(ArrayInit).getAnInit().getType().getName() = "Class<" + validatorClassName + ">" and
      // isValid method should be declared inside the validatorClass
      m.getDeclaringType() = validatorClass and
      // and it should have a name "isValid"
      m.getName() = "isValid" and
      // should be in the source
      m.fromSource() and
      this = constraintAnnotation.getAnnotatedElement()
    )
  }

  predicate hasValidator(Method m) {
    exists(Annotation constraintAnnotation, 
            string validatorClassName, 
            Class validatorClass | 
      // connect validatorClassName and validatorClass as they should
      validatorClass.hasName(validatorClassName) and
      // Check if the particular annotation's type has a `@Constraint` annotation
      constraintAnnotation.getType().getAnAnnotation().getType().hasQualifiedName("javax.validation", "Constraint") and
      // Get the value of the "validatedBy" in the `@Constraint` annotation and map it's class to validatorClass
      constraintAnnotation.getType().getAnAnnotation().getValue("validatedBy").(ArrayInit).getAnInit().getType().getName() = "Class<" + validatorClassName + ">" and
      // isValid method should be declared inside the validatorClass
      m.getDeclaringType() = validatorClass and
      // and it should have a name "isValid"
      m.getName() = "isValid" and
      // should be in the source
      m.fromSource() and
      this = constraintAnnotation.getAnnotatedElement()
    )
  }
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
