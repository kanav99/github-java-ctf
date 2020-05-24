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
        ma.getConstructedType().getErasure().(Class).hasQualifiedName("java.util", "HashSet")
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
      exists(Method isValid, ParameterizedInterface originalConstrainValidator, Method originalIsValid |
          source.asParameter() = isValid.getParameter(0) and
          isValid.hasName("isValid") and 
          isValid.getDeclaringType().hasSupertype(originalConstrainValidator) and
          originalConstrainValidator.getSourceDeclaration() instanceof TypeConstraintValidator and
          originalIsValid.hasName("isValid") and
          originalIsValid.getDeclaringType() = originalConstrainValidator and
          isValid.overrides(originalIsValid)
      )
    }

    override predicate isSink(DataFlow::Node sink) { 
      exists(MethodAccess sinkFunction, Interface constraintValidatorContext | 
        sink.asExpr() = sinkFunction.getArgument(0) and
        sinkFunction.getMethod().hasName("buildConstraintViolationWithTemplate") and
        sinkFunction.getQualifier().getType() = constraintValidatorContext and
        constraintValidatorContext.hasQualifiedName("javax.validation", "ConstraintValidatorContext")
      )
    }
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"

