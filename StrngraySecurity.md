# Stingray Security

Work in progress...

## Authorization for Jax-Rs Resources

*Allow access to a single resource method*

```java
@StingraySecurityOverride
public Response getExample() {
    return Response.ok().build();
}
```