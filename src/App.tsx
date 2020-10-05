import React, { useState } from 'react';
// import Editor from 'react-simple-code-editor';
import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
// import { highlight, languages } from 'prismjs/components/prism-core';
// import 'prismjs/components/prism-clike';
// import 'prismjs/components/prism-javascript';
import './App.css';

import 'bootstrap/dist/css/bootstrap.min.css';

function App() {
  return (
    <Container>
      <Row>
        <Col>Navigation</Col>
        <Col>
          <Row>Static Code</Row>
          <Row>User-Provided Code</Row>
        </Col>
        <Col>
          <Row>Type Environment</Row>
          <Row>Type Definitions</Row>  
        </Col>
      </Row>
    </Container>
  );
}

export default App;
