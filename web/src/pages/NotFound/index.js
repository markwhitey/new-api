import React from 'react';
import { Message } from 'semantic-ui-react';

const NotFound = () => (
  <>
    <Message warning>
      <Message.Header>正在处理中.....</Message.Header>
      <p>请稍后</p>
    </Message>
  </>
);

export default NotFound;
