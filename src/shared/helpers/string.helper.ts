export function maskString(text: string) {
  const [username, domain] = text.split('@');
  const maskedUsername =
    username.charAt(0) + '****' + username.charAt(username.length - 1);
  return maskedUsername + '@' + domain;
}
