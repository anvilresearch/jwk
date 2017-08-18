'use strict'

/**
 * Private JWK
 */
const RSAPrivateJWK = {
  kty: 'RSA',
  alg: 'RS256',
  n: 'v_jmSBwkn_3JaUX0-NRwuV-KFjVGjzdH3MctzO90QC2Uq5t3grXmC8YZlwXaNPWPI3hpy8nqGvXdpdZa6WcAmW-HQ31_2nMuVveKshgHJaUNNkmmkit3UVZbA5eR_ce1qDJXwr0V8NS53Zfzk3RHOmxoGzZy6O7nAXb1VQfWqrRjCrWO-HR1hOgOlQrDbqTE6qnFbBM2lcQDKIymeF60YTfvpfDu943GQC8GFgAVDUSxPMMFE6-BRd68UAPJWc0EvWTi1Qxd8xsWA3IWiG90oknfO_6IF8myBBdNpuDIyRwU5F8TxLrQnwyjGSc9kAAyXCE3LAMB_jBmGEw--vgTGQWaltGsgJBhWbnGy1oHnuCYwN1PEJo4w1EznpQTDuLdRe239G4r9n4hwXTWDSz8zh7-I1o_Rm-SS0UQiVWTCBusPE80he1vPZHYdsSqD4nrzrXKmglw6qyutinLdffC0iILd9-79oLU6l0lmomvRmiW0T57mC4fVb4Vj2dxIe1Tf0dnHZNg1h-REh3NzORv-yDO8ga0Y7864KmvdPBbmIW2zSKE84WEpVWJIID54tF73JvOWa3g0uPeG9FZbde-Ge9wb5VObW0Q_WcW_gPhT7qNKEfvuYoRrjtTxwjgb1NSLOkTaubFzZ31d5OZuZPxgkKOmvtCDVnyGQDkDSPRVus',
  e: 'AQAB',
  d: 'Xi1mE6Qy14Zyg8G9H0FhF5_mJ2T1e5b8GzRfpLUoS7_QuqtnYumHtOj3bt6BIRACq70L8dzZi2Zo2U2ihfRxF9Td_98WlP2Ck0mXci1VfENPiv1wyS6nt3Bs8AMwrNaHqL8hzLhkhiRmFm7QINufgeri287Haryg-Vf5nUBeMJqUKBHP1NWVPaF2XenM3H_a1uB4qL94PNrPTdpKZKzZQwRk_fyHz0xvINew3aQmr76uUIe_-ttTyQovSfXBltt8YsmWejw57uSv1ProUQCUsHUbHdyNuVXKjjU8dAy8k-TB3xNBqHaZmB1j-hgFHJrsGcR1w5KqLKBjxbHKB-chvn_thgTwSGJ3IPsDESAuvbrkg-eSslC_86LmMMq1-HORPugRCROv4qx0aBkkb71Vn0di9_xxVpXJ0xn9_No0BiTTsOa1becPeqzsG0l1X3Ed1UVaAdG-iu7gQjyz4l0l5nOi55aI2LIyB_H4PxJNUBJlmJtYp7uUj9OMgeCByxTzNSOejsZsoHNI_mlzvaU4_qTWVMJt7McyYV8Ijh7nKtoRywF8_z3Ye-KJSh1e549oGyB0nMJM-PlWzqGSLlf17lgEXbuN2uvV9uIr3WyEMUwnTAV-sCCVrrbS6q-GBcH2z5o6oZ7-FAenGEboP-fpJYGposx8gNrDrCcoFySCneE',
  p: '6dzofOLyvZO7JZSlWfsSn_8saijx6EXft9OizeY6eu05pQLu6-KSCVwOy6ndt5Nh3x0rSYFHh2QPU9aq4L2UVS24QIQCSlQ8G_PftLillZ_StwdO9abfhW9ldoN_H-7REAqU0mv0CylFkoKMHKOWXLt2KhtvPeQYZqPPqO0qo_sDH_JTZ93kKaOtWHxg5jxU0N9o78bHnb5CHu-KOZsaZC5MbrMCf0qX_7uBBBrhduwfAVKREKLnPVdNAHeaQKw71TSCMx0_S_VNpavcB-3ZFcnFDfekPHE1b-cyUJRp6TkK4PVI-BtX0lbmKnMVk7teYDZblRCZR2uRBIuEVu590Q',
  q: '0iTf3J2vuLTMCQc4zjKDbtHiQggofklTevnL0TR46-ClFqXWBfIa--8O7NEvCdgw9hK1EwA8JR0huTWsi9692-YFh_6UuHk-PhP7FPAsK3-FpeyBZBhrmU680ICTmWBw0ZexicMGap9K-bF_9z8XExDEiNDqS84QQ_ESoglZDR2UBuBZ3C27dWLlyE2A6RqsLpC654fEz1RG8awvSmWci6rP7y4RpcvGTVyVTG999piK90WS4GIZfuQxA3gL3g-EKMikK3ASVb-otzZwzRxyknHmEx1f0D53yY5QTaBrrxiWRFPlY5SgggurdLE4XxVY-qkskSwFM46ziJogYFQL-w',
  dp: 'tzLZYPO76ixvP4pJWcqoFXQky-jVT_pkvbFpaNhA2Yk6TfyVQ23SrshRwtOHn0YyNkC4ZzWB3hrRMwEIDVQVfgB5xPhkfuurxs3tYbn_5M01mTF9dkxJ71KLbiKmlFJVrbZMTOZKX-_t0063CbxQjsY_U873_sjPIKCUjSV08M4y7XS8R7J4CPJyWc3dbp62ZoWMw8C5IOYpD-jgJC5Pp0jpkRJkE2lQ1wGAmMGh-7IOu899WkXy1YetB3-p8524pVUj5Xy02AEK2Yxeqkt1cm8EEeP74Wlhzg6TyLHqocuQrRcZGVr6Ggj-9yP-NCNkVARhC83b9SnbiW7ttdfP8Q',
  dq: 'D72dWxwgpng8dEyrL57PA4ULKqELz3HUo_iEENaaXCjGlOy1HFrnNInSl2CP4m_kMvpxv8ubtbf557KiixOTKx6OuYITR8IlLGc4vnfDBzsVGrmdc470uFYShJes9qcnrDttnAEUwPXPmuZ1zGJYayAtaIYllqoHw98R4ztKBVZ62Q0DDiAK058l0RwlFNDfptlGdsNPtav9aGraW_tCf5-61ZKg1cduwiq2MDSFvevtNNpsRwxyFnQnS7g5Q1fsMVXeHjbV2MBzdc3JI0QHPPr1HedsXt_e_yT-1OG4TzRLRTD3lL70Sulu3V3M-CpUMOptIS6n8RW2Uvwggrao8w',
  qi: 'ZYYxFxSm1Se8uH79tJ3UfSiOoQEc9lHNz9ACKxOJKCsB7a5THpKEe7sfTnNm5EqimPB3Ua1gNftXh2GyXCFRyysvADCrL_dhUtMCCo78ij3FzwpnGDo3uEe9Z_7-JXLHD25BYNDMBMNEmfAFMxK-2IWcVAT6VzgtTr4jhLuTQdbkTL4zT4XbExwxKH-77WbfQBnDVn4WZ9j74T7AoeQ4exaZSImywIW5BnnoS_AG-QWK3HOS5pNA42M0Xj2L6ISeN9INpuDAJiLNG3xFsjOJP9QZirRG3J2pVEKMQF4P74Mf5oYFdTFmrrDjJ6zOPHuSe1oc9pmJAdnzTMR8yIErJA',
  key_ops: ['sign'],
  ext: true
}

/**
 * Public JWK
 */
const RSAPublicJWK = {
  kty: 'RSA',
  alg: 'RS256',
  n: 'v_jmSBwkn_3JaUX0-NRwuV-KFjVGjzdH3MctzO90QC2Uq5t3grXmC8YZlwXaNPWPI3hpy8nqGvXdpdZa6WcAmW-HQ31_2nMuVveKshgHJaUNNkmmkit3UVZbA5eR_ce1qDJXwr0V8NS53Zfzk3RHOmxoGzZy6O7nAXb1VQfWqrRjCrWO-HR1hOgOlQrDbqTE6qnFbBM2lcQDKIymeF60YTfvpfDu943GQC8GFgAVDUSxPMMFE6-BRd68UAPJWc0EvWTi1Qxd8xsWA3IWiG90oknfO_6IF8myBBdNpuDIyRwU5F8TxLrQnwyjGSc9kAAyXCE3LAMB_jBmGEw--vgTGQWaltGsgJBhWbnGy1oHnuCYwN1PEJo4w1EznpQTDuLdRe239G4r9n4hwXTWDSz8zh7-I1o_Rm-SS0UQiVWTCBusPE80he1vPZHYdsSqD4nrzrXKmglw6qyutinLdffC0iILd9-79oLU6l0lmomvRmiW0T57mC4fVb4Vj2dxIe1Tf0dnHZNg1h-REh3NzORv-yDO8ga0Y7864KmvdPBbmIW2zSKE84WEpVWJIID54tF73JvOWa3g0uPeG9FZbde-Ge9wb5VObW0Q_WcW_gPhT7qNKEfvuYoRrjtTxwjgb1NSLOkTaubFzZ31d5OZuZPxgkKOmvtCDVnyGQDkDSPRVus',
  e: 'AQAB',
  key_ops: ['verify'],
  ext: true
}

/**
 * Exports
 * @ignore
 */
module.exports = {
  RSAPrivateJWK,
  RSAPublicJWK
}
