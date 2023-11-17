import { Schema, model } from "mongoose";
import Joi from "joi";
import { handleSaveError, preUpdate } from "./hooks.js";

const contactSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Set name for contact"],
    },
    email: {
      type: String,
    },
    phone: {
      type: String,
    },
    favorite: {
      type: Boolean,
      default: false,
    },
  },
  { versionKey: false }
);

contactSchema.post("save", handleSaveError);
contactSchema.pre("findOneAndUpdate", preUpdate);
contactSchema.post("findOneAndUpdate", handleSaveError);

export const contactAddSchema = Joi.object({
  name: Joi.string().required().messages({
    "any.required": `missing required name field`,
    "string.base": `"name" must be text`,
  }),
  email: Joi.string().required().email().messages({
    "any.required": `missing required name field`,
    "string.base": `"email" must be text`,
  }),
  phone: Joi.string().required().messages({
    "any.required": `missing required name field`,
    "string.base": `"phone" must be text`,
  }),
  favorite: Joi.boolean(),
});
export const contactUpdateSchema = Joi.object({
  name: Joi.string(),
  email: Joi.string(),
  phone: Joi.string(),
  favorite: Joi.boolean(),
});
export const contactFavoriteSchema = Joi.object({
  favorite: Joi.boolean().required(),
});

const Contact = model("contact", contactSchema);

export default Contact;
