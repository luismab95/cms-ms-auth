export interface EmailInterface {
  to: string;
  from: string;
  subject: string;
  templateName: string;
  context: any;
}
