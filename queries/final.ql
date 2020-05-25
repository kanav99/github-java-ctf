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
    exists(TryStmt t, CatchClause c, MethodAccess throwingCall, MethodAccess errorWriter |
      // connect try and catch
      c.getTry() = t and
      // in catch, the method access would be the successor...
      errorWriter = succ.asExpr() and
      // restricting to those methods that write something
      (
        errorWriter.getMethod().getName() in [
          "getMessage", "getStackTrace",
          "getSuppressed", "toString",
          "getLocalizedMessage" ] or
        errorWriter.getMethod().getName().prefix(3) = "get" or
        errorWriter.getMethod() instanceof GetterMethod
      ) and
      // and it's qualifier should be the error variable.
      c.getVariable().getAnAccess() = errorWriter.getQualifier() and
      // predecessor would be an argument of a method access...
      throwingCall.getAnArgument() = pred.asExpr() and
      // which is contained in the try statement
      throwingCall.getEnclosingStmt().getParent*() = t.getBlock() and
      // and the method should throw some subtype of the caught clause type
      throwingCall.getMethod().getAThrownExceptionType().getASupertype*() = c.getACaughtType() and
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

