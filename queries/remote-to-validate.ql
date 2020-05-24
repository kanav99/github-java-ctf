/** 
* @kind path-problem 
*/
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph
import semmle.code.java.dataflow.FlowSources

class TypeConstraintValidator extends GenericInterface {
  TypeConstraintValidator() { hasQualifiedName("javax.validation", "ConstraintValidator") }
}

class CustomStepper extends TaintTracking::AdditionalTaintStep {

  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    // from `a` to `a.b()`
    exists(MethodAccess ma |
        succ.asExpr() = ma and
        pred.asExpr() = ma.getQualifier()
    ) or
    // from `a` to `new Class(a)`
    exists(ConstructorCall ma |
        succ.asExpr() = ma and
        ma.getAnArgument() = pred.asExpr()
    ) or
    // from `a` to `func(a)`: too general
    exists(MethodAccess ma |
        succ.asExpr() = ma and
        pred.asExpr() = ma.getAnArgument()
    ) or
    // forEach handler
    exists( LambdaExpr l, MethodAccess ma |
        l.asMethod().getAParameter() = succ.asParameter() and
        ma.getAnArgument() = l and
        ma.getMethod().getName() = "forEach" and
        ma.getQualifier() = pred.asExpr()
    )
  }
}

class MyTaintTrackingConfig extends TaintTracking::Configuration {
    MyTaintTrackingConfig() { this = "MyTaintTrackingConfig" }

    override predicate isSource(DataFlow::Node source) { 
        source instanceof RemoteFlowSource
    }

    override predicate isSink(DataFlow::Node sink) { 
        exists(MethodAccess c | 
            sink.asExpr() = c.getAnArgument() and
            c.getMethod().hasName("validate") and
            c.getMethod().getDeclaringType().hasQualifiedName("com.netflix.titus.common.model.sanitizer", "EntitySanitizer")
        )
    }
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
