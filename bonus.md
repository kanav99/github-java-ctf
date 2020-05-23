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
