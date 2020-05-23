# Bonus

Though query helps us find where all the validated sources are, but this doesn't help us to find the data that is directly controlled by the user. To find them, thanks to CodeQL we have `RemoteFlowSource` class which points out all the nodes directly controlled by the user. We can use this simple query to find all the sources that are controlled by remote user:

```codeql
 predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
```
To find all the fields/beans in which tainted data flow from remote sources and then it flows to `isValid` method as a parameter, it is important to first get all the fields/classes that are validated by a particular `isValid` method. For example, `softConstraints` field in `Container` class is validated directly by `SchedulingConstraintValidator.isValid`, `Container` is validated by `SchedulingConstraintSetValidator.isValid`. To get this mapping in CodeQL, first we need to make a memory map how it should be done

1. `softConstraints` has an annotation `@SchedulingConstraintValidator.SchedulingConstraint`
2. Type of this annotation has an annotation `@Constraint(validatedBy = {SchedulingConstraintValidator.class})`
3. `SchedulingConstraintValidator` has a method `isValid`

We need to translate this in CodeQL

```codeql
from Annotation constraintAnnotation, string validatorClassName, 
Class validatorClass, Method m
where
  // connect validatorClassName and validatorClass as they should
  validatorClass.hasName(validatorClassName) and
  // Check if the particular annotation's type has a `@Constraint` annotation
  constraintAnnotation.getType().getAnAnnotation().getType().hasQualifiedName("javax.validation", "Constraint") and
  // Get the value of the "validatedBy" in the `@Constraint` annotation and map it's class to validatorClass
  constraintAnnotation.getType().getAnAnnotation().getValue("validatedBy").(ArrayInit).getAnInit().getType().getName() = "Class<" + validatorClassName + ">" and
  // isValid method should be declared inside the validatorClass
  m.getDeclaringType() = validatorClass and
  // and it should have a name "isValid"
  m.getName() = "isValid"

select constraintAnnotation.getAnnotatedElement(), m
```

We get a neat mapping of an constraint annotation with it's validator. We can also restrict it to source. Now with this query in our hands, we are ready to map these fields/classes to some remote source.

Using this query, I made new classes `ValidatedClass` and `ValidatedField`

```codeql
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

```

## Alternate usage of RemoteFlowSource

Now we will make use of `RemoteFlowSource` to find all remote user controlled data which finally lead to `buildConstraintViolationWithTemplate`.

As `isValid` function is called by a library function, not inside the source, we need to find the last expressionn which calls a library function that finally lead to the `isValid` functions. To get this we add a breakpoint inside the `isValid` function of `SchedulingConstraintSetValidator.java` just to get a complete call stack, and make a job requests.

![](/images/3.2.1.png)

We observe that the class `DefaultEntitySanitizer` is called which calls `validate` function, which calls some internal library functions that finally lead to `isValid` function. To make it more general, we see that `DefaultEntitySanitizer` extends `EntitySanitizer`, so we set the sink to the `validate` function of `EntitySanitizer` and set the source to `RemoteFlowSource`. 

```codeql
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
```

![](/images/3.2.2.png)

(complete query is available [here](/queries/remote-to-validate.ql))

We find 18 such paths. We see that the following types are the source of such paths

* SystemSelector
* JobDescriptor
* String
* ScalableTargetResourceInfo
* Capacity
* JobCapacityWithOptionalAttributes

All these are the sources that may be validated and eventually may be a source of an RCE. But as we know that not all types are validated (as in section 1.2), all these reduce to a much smaller number.

