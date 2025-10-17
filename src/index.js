const express = require('express');
const fs = require('fs');
const csv = require('csv-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const PORT = process.env.PORT || 3000;
const DICTIONARY_PATH = './src/data/1millionPasswords.csv';

app.use(express.json());
app.use(helmet({
  contentSecurityPolicy: false,
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes. Intente más tarde.' }
});
app.use(limiter);

// -------------------- CONFIGURACIÓN SWAGGER --------------------
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Evaluación de Contraseñas',
      version: '1.0.0',
      description: `API RESTful para evaluar la fortaleza de contraseñas mediante el cálculo de entropía.

## Fórmula de Entropía
\`E = L × log₂(N)\`

Donde:
- **E**: Entropía en bits
- **L**: Longitud de la contraseña
- **N**: Tamaño del alfabeto (keyspace)

## Categorías de Fortaleza
- **0-60 bits**: Débil o Aceptable
- **60-80 bits**: Fuerte
- **80+ bits**: Muy Fuerte
- **Común**: Insegura (encontrada en diccionario de 1M contraseñas)`,
      contact: {
        name: 'Soporte API',
        email: 'soporte@ejemplo.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Servidor de Desarrollo'
      }
    ],
    tags: [
      {
        name: 'Password',
        description: 'Operaciones de evaluación de contraseñas'
      },
      {
        name: 'System',
        description: 'Endpoints del sistema'
      }
    ],
    components: {
      schemas: {
        PasswordRequest: {
          type: 'object',
          required: ['password'],
          properties: {
            password: {
              type: 'string',
              minLength: 1,
              maxLength: 256,
              description: 'Contraseña a evaluar',
              example: 'MiContraseña2024!'
            }
          }
        },
        EvaluationResult: {
          type: 'object',
          properties: {
            longitud: {
              type: 'integer',
              description: 'Longitud de la contraseña (L)',
              example: 14
            },
            keyspace: {
              type: 'integer',
              description: 'Tamaño del alfabeto (N)',
              example: 68
            },
            entropia_bits: {
              type: 'number',
              format: 'float',
              description: 'Entropía calculada en bits',
              example: 85.22
            },
            entropia_original: {
              type: 'number',
              format: 'float',
              nullable: true,
              description: 'Entropía antes de penalización',
              example: null
            },
            categoria: {
              type: 'string',
              enum: ['Débil o Aceptable', 'Fuerte', 'Muy Fuerte', 'Insegura (Común)'],
              description: 'Categoría de fortaleza',
              example: 'Muy Fuerte'
            },
            en_diccionario: {
              type: 'boolean',
              description: 'Si está en diccionario de contraseñas comunes',
              example: false
            },
            tiempo_estimado_crack: {
              type: 'string',
              description: 'Tiempo estimado para crackear',
              example: '143323.75 siglos'
            }
          }
        },
        PasswordResponse: {
          type: 'object',
          properties: {
            password_evaluada: {
              type: 'string',
              description: 'Contraseña ofuscada',
              example: '**************'
            },
            resultado: {
              $ref: '#/components/schemas/EvaluationResult'
            }
          }
        },
        Error: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              example: 'Contraseña inválida o ausente.'
            },
            detalles: {
              type: 'string',
              example: '"password" is required'
            }
          }
        }
      }
    },
    paths: {
      '/api/v1/password/evaluate': {
        post: {
          tags: ['Password'],
          summary: 'Evaluar fortaleza de contraseña',
          description: `Calcula la entropía de una contraseña y determina su nivel de seguridad.

La API verifica:
- Longitud de la contraseña (L)
- Complejidad del alfabeto usado (N)
- Si está en un diccionario de 1 millón de contraseñas comunes
- Tiempo estimado de crackeo (asumiendo 10¹¹ intentos/segundo)`,
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PasswordRequest'
                },
                examples: {
                  fuerte: {
                    summary: 'Contraseña fuerte',
                    value: {
                      password: 'edier2004$2004'
                    }
                  },
                  debil: {
                    summary: 'Contraseña débil',
                    value: {
                      password: '123456'
                    }
                  },
                  comun: {
                    summary: 'Contraseña común',
                    value: {
                      password: 'password123'
                    }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Evaluación exitosa',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/PasswordResponse'
                  },
                  examples: {
                    fuerte: {
                      summary: 'Resultado de contraseña fuerte',
                      value: {
                        password_evaluada: '**************',
                        resultado: {
                          longitud: 14,
                          keyspace: 68,
                          entropia_bits: 85.22,
                          entropia_original: null,
                          categoria: 'Muy Fuerte',
                          en_diccionario: false,
                          tiempo_estimado_crack: '143323.75 siglos'
                        }
                      }
                    },
                    comun: {
                      summary: 'Resultado de contraseña común',
                      value: {
                        password_evaluada: '***********',
                        resultado: {
                          longitud: 11,
                          keyspace: 36,
                          entropia_bits: 28,
                          entropia_original: 56.77,
                          categoria: 'Insegura (Común)',
                          en_diccionario: true,
                          tiempo_estimado_crack: '42.95 minutos'
                        }
                      }
                    }
                  }
                }
              }
            },
            '400': {
              description: 'Error de validación',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/Error'
                  }
                }
              }
            },
            '429': {
              description: 'Demasiadas solicitudes',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      error: {
                        type: 'string',
                        example: 'Demasiadas solicitudes. Intente más tarde.'
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/api/v1/health': {
        get: {
          tags: ['System'],
          summary: 'Health Check',
          description: 'Verifica el estado del servicio y del diccionario de contraseñas',
          responses: {
            '200': {
              description: 'Servicio operativo',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      status: {
                        type: 'string',
                        example: 'OK'
                      },
                      timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: '2024-10-16T12:00:00.000Z'
                      },
                      dictionary_loaded: {
                        type: 'boolean',
                        example: true
                      },
                      dictionary_size: {
                        type: 'integer',
                        example: 1000000
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  apis: [] // No necesitamos archivos ya que definimos todo en 'definition'
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Servir documentación Swagger
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'API Password Evaluator',
}));

// Servir spec JSON
app.get('/api-docs.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// -------------------- CARGA DE DICCIONARIO --------------------
let passwordSet = new Set();

function loadDictionary() {
  return new Promise((resolve, reject) => {
    const set = new Set();
    fs.createReadStream(DICTIONARY_PATH)
      .pipe(csv())
      .on('data', (row) => {
        const values = Object.values(row);
        if (values[2]) {
          set.add(String(values[1]).toLowerCase().trim());
        }
      })
      .on('end', () => {
        console.log(`📘 Diccionario cargado: ${set.size} contraseñas`);
        resolve(set);
      })
      .on('error', (err) => reject(err));
  });
}

// -------------------- FUNCIONES DE CÁLCULO --------------------
function calculate_L(password) {
  return password.length;
}

function calculate_N(password) {
  const lower = /[a-z]/.test(password);
  const upper = /[A-Z]/.test(password);
  const digit = /[0-9]/.test(password);
  const symbol = /[^A-Za-z0-9]/.test(password);

  let N = 0;
  if (lower) N += 26;
  if (upper) N += 26;
  if (digit) N += 10;
  if (symbol) N += 32;
  
  return N === 0 ? 1 : N;
}

function calculate_entropy(password) {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const entropy = L * Math.log2(N);
  return { entropy, L, N };
}

function estimate_crack_time_seconds(entropy, guessesPerSecond = 1e11) {
  const possibilities = Math.pow(2, entropy);
  return possibilities / guessesPerSecond;
}

function humanize_time(seconds) {
  if (seconds < 1) return `${(seconds * 1000).toFixed(2)} ms`;
  
  const units = [
    { label: 'segundos', secs: 1 },
    { label: 'minutos', secs: 60 },
    { label: 'horas', secs: 3600 },
    { label: 'días', secs: 86400 },
    { label: 'años', secs: 31536000 },
    { label: 'siglos', secs: 3153600000 },
    { label: 'milenios', secs: 31536000000 }
  ];
  
  let unit = units.find(u => seconds < u.secs * 60) || units[units.length - 1];
  const value = (seconds / unit.secs).toFixed(2);
  return `${value} ${unit.label}`;
}

function check_password_strength(password) {
  const { entropy, L, N } = calculate_entropy(password);

  let category = '';
  if (entropy < 60) category = 'Débil o Aceptable';
  else if (entropy < 80) category = 'Fuerte';
  else category = 'Muy Fuerte';

  const inDictionary = passwordSet.has(password.toLowerCase());
  
  let adjustedEntropy = entropy;
  if (inDictionary) {
    category = 'Insegura (Común)';
    adjustedEntropy = Math.min(entropy, 28);
  }

  const crackSeconds = estimate_crack_time_seconds(adjustedEntropy);

  return {
    longitud: L,
    keyspace: N,
    entropia_bits: parseFloat(adjustedEntropy.toFixed(2)),
    entropia_original: inDictionary ? parseFloat(entropy.toFixed(2)) : null,
    categoria: category,
    en_diccionario: inDictionary,
    tiempo_estimado_crack: humanize_time(crackSeconds)
  };
}

// -------------------- ENDPOINTS --------------------

app.post('/api/v1/password/evaluate', (req, res) => {
  const schema = Joi.object({
    password: Joi.string().min(1).max(256).required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Contraseña inválida o ausente.',
      detalles: error.details[0].message 
    });
  }

  const { password } = req.body;
  const result = check_password_strength(password);

  res.json({
    password_evaluada: password.replace(/./g, '*'),
    resultado: result
  });
});

app.get('/api/v1/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    dictionary_loaded: passwordSet.size > 0,
    dictionary_size: passwordSet.size
  });
});

app.get('/', (req, res) => {
  res.redirect('/api-docs');
});

// Manejo de rutas no encontradas
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint no encontrado',
    documentacion: '/api-docs',
    endpoints_disponibles: [
      'POST /api/v1/password/evaluate',
      'GET /api/v1/health',
      'GET /api-docs',
      'GET /api-docs.json'
    ]
  });
});

(async () => {
  try {
    passwordSet = await loadDictionary();
    app.listen(PORT, () => {
      console.log(`🚀 API ejecutándose en http://localhost:${PORT}`);
      console.log(`📖 Documentación Swagger en http://localhost:${PORT}/api-docs`);
      console.log(`💚 Health check en http://localhost:${PORT}/api/v1/health`);
    });
  } catch (err) {
    console.error('❌ Error al cargar el diccionario:', err);
    process.exit(1);
  }
})();
